"""
Hardware Analyzers
==================
Analisadores de recursos de hardware do host: disco, memória, CPU e temperatura.
"""

import logging
import re

from src.collector.system_collector import SystemData
from src.analyzer.models import Severity, Issue, DiagnosticResult, _has_output

logger = logging.getLogger(__name__)

# Thresholds
DISK_WARNING_PCT = 80
DISK_CRITICAL_PCT = 90
MEM_WARNING_PCT = 85
MEM_CRITICAL_PCT = 95
TEMP_WARNING_C = 70
TEMP_CRITICAL_C = 85
LOAD_WARNING_MULTIPLIER = 1.5   # load > 1.5 * núcleos = warning
LOAD_CRITICAL_MULTIPLIER = 3.0  # load > 3.0 * núcleos = critical


def analyze_disk(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa uso de disco. Alerta quando próximo da capacidade máxima."""
    if not _has_output(data.disk_usage):
        return

    lines = data.disk_usage.stdout.splitlines()
    for line in lines[1:]:  # pula cabeçalho
        parts = line.split()
        if len(parts) < 6:
            continue

        filesystem = parts[0]
        use_pct_str = parts[4].rstrip("%")

        # Ignora tmpfs, devtmpfs, filesystems virtuais e snap loop-mounts
        # (snap packages são squashfs read-only — sempre aparecem como 100% cheios por design)
        if any(skip in filesystem for skip in ["tmpfs", "devtmpfs", "udev", "none", "/dev/loop"]):
            continue

        try:
            use_pct = int(use_pct_str)
        except ValueError:
            continue

        mountpoint = parts[5]
        size = parts[1]
        used = parts[2]
        available = parts[3]

        if use_pct >= DISK_CRITICAL_PCT:
            result.issues.append(Issue(
                severity=Severity.CRITICAL,
                category="Armazenamento",
                title=f"Disco crítico: {mountpoint} com {use_pct}% de uso",
                description=(
                    f"O ponto de montagem '{mountpoint}' ({filesystem}) está com "
                    f"{use_pct}% de uso ({used}/{size}, livre: {available})."
                ),
                recommendation=(
                    "Ação imediata necessária. Limpe arquivos desnecessários, "
                    "arquive logs antigos ou expanda o volume. "
                    "Disco cheio pode causar falhas em serviços e corrupção de dados."
                ),
                raw_evidence=line,
            ))
        elif use_pct >= DISK_WARNING_PCT:
            result.issues.append(Issue(
                severity=Severity.WARNING,
                category="Armazenamento",
                title=f"Disco alto: {mountpoint} com {use_pct}% de uso",
                description=(
                    f"O ponto de montagem '{mountpoint}' ({filesystem}) está com "
                    f"{use_pct}% de uso ({used}/{size}, livre: {available})."
                ),
                recommendation=(
                    "Monitore o crescimento do disco. "
                    "Considere limpeza de logs, backups e arquivos temporários. "
                    f"Alerta crítico em {DISK_CRITICAL_PCT}%."
                ),
                raw_evidence=line,
            ))
        else:
            result.issues.append(Issue(
                severity=Severity.INFO,
                category="Armazenamento",
                title=f"Disco normal: {mountpoint} com {use_pct}% de uso",
                description=f"Uso de disco em {mountpoint}: {used}/{size} ({use_pct}%)",
                recommendation="Sem ação necessária.",
                raw_evidence=line,
            ))


def analyze_memory(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa uso de memória RAM e swap."""
    if not _has_output(data.memory):
        return

    lines = data.memory.stdout.splitlines()
    mem_line = next((l for l in lines if l.startswith("Mem:")), None)
    swap_line = next((l for l in lines if l.startswith("Swap:")), None)

    if mem_line:
        parts = mem_line.split()
        # free -m: Mem: total used free shared buff/cache available
        if len(parts) >= 7:
            try:
                total = int(parts[1])
                used = int(parts[2])
                available = int(parts[6])
                use_pct = (used / total * 100) if total > 0 else 0

                if use_pct >= MEM_CRITICAL_PCT:
                    result.issues.append(Issue(
                        severity=Severity.CRITICAL,
                        category="Memória",
                        title=f"Memória crítica: {use_pct:.0f}% em uso",
                        description=(
                            f"RAM: {used}MB usados de {total}MB total "
                            f"({available}MB disponíveis). "
                            f"Sistema está sob severa pressão de memória."
                        ),
                        recommendation=(
                            "Identifique processos consumindo mais memória com 'ps aux --sort=-%mem'. "
                            "Considere reiniciar serviços com vazamento de memória ou adicionar RAM."
                        ),
                        raw_evidence=mem_line,
                    ))
                elif use_pct >= MEM_WARNING_PCT:
                    result.issues.append(Issue(
                        severity=Severity.WARNING,
                        category="Memória",
                        title=f"Memória alta: {use_pct:.0f}% em uso",
                        description=(
                            f"RAM: {used}MB usados de {total}MB total "
                            f"({available}MB disponíveis)."
                        ),
                        recommendation=(
                            "Monitore o consumo de memória. "
                            "Verifique processos com alto uso de RAM."
                        ),
                        raw_evidence=mem_line,
                    ))
                else:
                    result.issues.append(Issue(
                        severity=Severity.INFO,
                        category="Memória",
                        title=f"Memória normal: {use_pct:.0f}% em uso",
                        description=f"RAM: {used}MB/{total}MB ({available}MB disponíveis)",
                        recommendation="Sem ação necessária.",
                        raw_evidence=mem_line,
                    ))
            except (ValueError, ZeroDivisionError):
                pass

    if swap_line:
        parts = swap_line.split()
        if len(parts) >= 3:
            try:
                swap_total = int(parts[1])
                swap_used = int(parts[2])

                if swap_total == 0:
                    result.issues.append(Issue(
                        severity=Severity.INFO,
                        category="Memória",
                        title="Sem swap configurado",
                        description="Nenhuma partição swap ativa no sistema.",
                        recommendation=(
                            "Em sistemas com pouca RAM, swap pode evitar OOM kills. "
                            "Considere criar um swapfile se necessário."
                        ),
                    ))
                elif swap_used > 0:
                    swap_pct = swap_used / swap_total * 100
                    severity = Severity.WARNING if swap_pct > 50 else Severity.INFO
                    result.issues.append(Issue(
                        severity=severity,
                        category="Memória",
                        title=f"Swap em uso: {swap_used}MB/{swap_total}MB ({swap_pct:.0f}%)",
                        description=(
                            f"O sistema está usando {swap_used}MB de swap. "
                            "Uso de swap indica pressão de memória."
                        ),
                        recommendation=(
                            "Alto uso de swap degrada performance. "
                            "Considere aumentar RAM ou reduzir carga de memória."
                        ),
                        raw_evidence=swap_line,
                    ))
            except (ValueError, ZeroDivisionError):
                pass


def analyze_cpu_load(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa carga da CPU comparando com número de núcleos."""
    if not _has_output(data.load_average) or not _has_output(data.cpu_info):
        return

    try:
        # /proc/loadavg: 1min 5min 15min running/total last_pid
        load_parts = data.load_average.stdout.split()
        load_1min = float(load_parts[0])
        load_5min = float(load_parts[1])
        load_15min = float(load_parts[2])

        # Número de núcleos (nproc)
        num_cpus_str = data.cpu_info.stdout.splitlines()[0].strip()
        num_cpus = int(num_cpus_str) if num_cpus_str.isdigit() else 1

        # Usa load de 5 minutos como referência (mais estável que 1min)
        load_ratio = load_5min / num_cpus

        if load_ratio >= LOAD_CRITICAL_MULTIPLIER:
            result.issues.append(Issue(
                severity=Severity.CRITICAL,
                category="CPU",
                title=f"Carga crítica: {load_5min:.2f} ({num_cpus} CPUs)",
                description=(
                    f"Load average: 1m={load_1min:.2f}, 5m={load_5min:.2f}, 15m={load_15min:.2f} "
                    f"com {num_cpus} núcleo(s). "
                    f"Carga {load_ratio:.1f}x acima da capacidade."
                ),
                recommendation=(
                    "Sistema sobrecarregado. Identifique processos com alto uso de CPU. "
                    "Use 'ps aux --sort=-%cpu | head -10' para encontrar os culpados."
                ),
                raw_evidence=data.load_average.stdout,
            ))
        elif load_ratio >= LOAD_WARNING_MULTIPLIER:
            result.issues.append(Issue(
                severity=Severity.WARNING,
                category="CPU",
                title=f"Carga elevada: {load_5min:.2f} ({num_cpus} CPUs)",
                description=(
                    f"Load average: 1m={load_1min:.2f}, 5m={load_5min:.2f}, 15m={load_15min:.2f} "
                    f"com {num_cpus} núcleo(s)."
                ),
                recommendation=(
                    "Monitore a carga da CPU. "
                    "Se persistir, identifique processos de alto consumo."
                ),
                raw_evidence=data.load_average.stdout,
            ))
        else:
            result.issues.append(Issue(
                severity=Severity.INFO,
                category="CPU",
                title=f"Carga normal: {load_5min:.2f} ({num_cpus} CPUs)",
                description=(
                    f"Load average: 1m={load_1min:.2f}, 5m={load_5min:.2f}, 15m={load_15min:.2f}"
                ),
                recommendation="Sem ação necessária.",
            ))
    except (ValueError, IndexError, ZeroDivisionError) as e:
        logger.debug(f"Não foi possível analisar CPU load: {e}")


def analyze_temperature(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa temperatura do sistema via sensors e thermal_zones."""
    temps_found = []

    # Verifica saída de sensors (lm-sensors)
    if _has_output(data.sensors):
        for line in data.sensors.stdout.splitlines():
            # Remove anotações de threshold entre parênteses antes de extrair temperatura
            # Ex: "+42.0°C  (high = +100.0°C, crit = +100.0°C)" → "+42.0°C"
            line_clean = re.sub(r"\(.*?\)", "", line)
            matches = re.findall(r"([+-]?\d+\.\d+)°?C", line_clean)
            for match in matches:
                try:
                    temp = float(match)
                    if 0 < temp < 150:  # faixa razoável
                        temps_found.append((line.strip(), temp))
                except ValueError:
                    pass

    # Verifica thermal_zones via sysfs
    if _has_output(data.vcgencmd_temp):
        text = data.vcgencmd_temp.stdout
        # Formato: "thermal_zone0: 45.0°C" ou "temp=45.0'C"
        matches = re.findall(r"(\d+\.?\d*)°?[C']", text)
        for match in matches:
            try:
                temp = float(match)
                if 0 < temp < 150:
                    temps_found.append((text.strip()[:80], temp))
            except ValueError:
                pass

    if not temps_found:
        result.issues.append(Issue(
            severity=Severity.INFO,
            category="Temperatura",
            title="Dados de temperatura não disponíveis",
            description="lm-sensors não instalado ou sem sensores detectados.",
            recommendation=(
                "Instale lm-sensors: 'sudo apt install lm-sensors && sudo sensors-detect'"
            ),
        ))
        return

    max_temp = max(t for _, t in temps_found)
    max_evidence = next(line for line, t in temps_found if t == max_temp)

    if max_temp >= TEMP_CRITICAL_C:
        result.issues.append(Issue(
            severity=Severity.CRITICAL,
            category="Temperatura",
            title=f"Temperatura crítica: {max_temp:.1f}°C",
            description=(
                f"Temperatura máxima detectada: {max_temp:.1f}°C. "
                f"Threshold crítico: {TEMP_CRITICAL_C}°C. "
                "Risco de throttling ou dano por superaquecimento."
            ),
            recommendation=(
                "Verifique ventilação e dissipação de calor imediatamente. "
                "Limpe poeira dos coolers. Verifique se o thermal paste está adequado. "
                "Reduza carga do sistema se possível."
            ),
            raw_evidence=max_evidence,
        ))
    elif max_temp >= TEMP_WARNING_C:
        result.issues.append(Issue(
            severity=Severity.WARNING,
            category="Temperatura",
            title=f"Temperatura elevada: {max_temp:.1f}°C",
            description=(
                f"Temperatura máxima: {max_temp:.1f}°C. "
                f"Threshold de alerta: {TEMP_WARNING_C}°C."
            ),
            recommendation=(
                "Monitore a temperatura. Verifique ventilação e cargas de trabalho."
            ),
            raw_evidence=max_evidence,
        ))
    else:
        result.issues.append(Issue(
            severity=Severity.INFO,
            category="Temperatura",
            title=f"Temperatura normal: {max_temp:.1f}°C",
            description=f"Temperatura máxima: {max_temp:.1f}°C — dentro do limite seguro.",
            recommendation="Sem ação necessária.",
        ))
