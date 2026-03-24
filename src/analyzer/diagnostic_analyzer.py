"""
Diagnostic Analyzer
====================
Módulo responsável pela análise dos dados coletados do sistema.
Identifica problemas, classifica por severidade e gera recomendações.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from src.collector.system_collector import SystemData, CommandResult

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Níveis de severidade dos problemas identificados."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Issue:
    """Representa um problema ou observação identificada durante o diagnóstico."""
    severity: Severity
    category: str
    title: str
    description: str
    recommendation: str
    raw_evidence: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.category}: {self.title}"


@dataclass
class DiagnosticResult:
    """
    Resultado completo da análise diagnóstica.
    Contém todos os problemas encontrados e um resumo executivo.
    """
    issues: List[Issue] = field(default_factory=list)
    summary: str = ""
    hostname: str = "desconhecido"
    os_info: str = "desconhecido"
    kernel: str = "desconhecido"
    uptime: str = "desconhecido"

    @property
    def critical_issues(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == Severity.CRITICAL]

    @property
    def warning_issues(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == Severity.WARNING]

    @property
    def info_issues(self) -> List[Issue]:
        return [i for i in self.issues if i.severity == Severity.INFO]

    @property
    def overall_health(self) -> str:
        """Avaliação geral da saúde do sistema."""
        if self.critical_issues:
            return "CRÍTICO"
        if self.warning_issues:
            return "ATENÇÃO"
        return "SAUDÁVEL"


class DiagnosticAnalyzer:
    """
    Analisa os dados coletados do sistema e identifica problemas.

    Cada método analyze_* verifica um aspecto específico do sistema
    e adiciona Issues à lista de resultados.
    """

    # Thresholds configuráveis
    DISK_WARNING_PCT = 80
    DISK_CRITICAL_PCT = 90
    MEM_WARNING_PCT = 85
    MEM_CRITICAL_PCT = 95
    TEMP_WARNING_C = 70
    TEMP_CRITICAL_C = 85
    LOAD_WARNING_MULTIPLIER = 1.5   # load > 1.5 * núcleos = warning
    LOAD_CRITICAL_MULTIPLIER = 3.0  # load > 3.0 * núcleos = critical

    # Padrões de erros críticos em dmesg/journalctl
    CRITICAL_PATTERNS = [
        r"kernel panic",
        r"oom.kill",
        r"out of memory",
        r"i/o error",
        r"hardware error",
        r"mce.*error",
        r"nvme.*error",
        r"sata.*error",
        r"ext[234].*error",
        r"filesystem.*error",
        r"read.*error.*sector",
        r"uncorrectable.*error",
    ]

    WARNING_PATTERNS = [
        r"usb.*disconnect",
        r"usb.*over.current",
        r"usb.*power",
        r"usb.*reset",
        r"segfault",
        r"cpu.*throttled",
        r"thermal.*throttling",
        r"watchdog",
        r"soft lockup",
        r"hung task",
        r"nfs.*server.*not responding",
        r"dropped packet",
        r"link is down",
    ]

    def analyze(self, data: SystemData) -> DiagnosticResult:
        """
        Executa a análise completa dos dados coletados.

        Args:
            data: Dados coletados pelo SystemCollector.

        Returns:
            DiagnosticResult com todos os problemas encontrados.
        """
        result = DiagnosticResult()

        # Extrai informações básicas do sistema
        result.hostname = self._safe_output(data.hostname)
        result.os_info = self._parse_os_info(data.os_info)
        result.kernel = self._safe_output(data.kernel)
        result.uptime = self._safe_output(data.uptime)

        logger.debug("Analisando: disco...")
        self._analyze_disk(data, result)

        logger.debug("Analisando: memória...")
        self._analyze_memory(data, result)

        logger.debug("Analisando: CPU/carga...")
        self._analyze_cpu_load(data, result)

        logger.debug("Analisando: temperatura...")
        self._analyze_temperature(data, result)

        logger.debug("Analisando: USB...")
        self._analyze_usb(data, result)

        logger.debug("Analisando: logs do sistema...")
        self._analyze_dmesg(data, result)

        logger.debug("Analisando: overruns em portas seriais...")
        self._analyze_tty_overruns(data, result)

        logger.debug("Analisando: erros em adaptadores USB-serial...")
        self._analyze_usb_serial(data, result)

        logger.debug("Analisando: erros críticos (journalctl)...")
        self._analyze_journalctl(data, result)

        logger.debug("Analisando: serviços com falha...")
        self._analyze_failed_services(data, result)

        # Gera resumo executivo
        result.summary = self._generate_summary(result)

        # Ordena por severidade: CRITICAL > WARNING > INFO
        severity_order = {Severity.CRITICAL: 0,
                          Severity.WARNING: 1, Severity.INFO: 2}
        result.issues.sort(key=lambda x: severity_order[x.severity])

        logger.info(
            f"Análise concluída: {len(result.critical_issues)} crítico(s), "
            f"{len(result.warning_issues)} aviso(s), "
            f"{len(result.info_issues)} info(s)"
        )

        return result

    # ------------------------------------------------------------------ #
    # Métodos de análise individuais
    # ------------------------------------------------------------------ #

    def _analyze_disk(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa uso de disco. Alerta quando próximo da capacidade máxima."""
        if not self._has_output(data.disk_usage):
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

            if use_pct >= self.DISK_CRITICAL_PCT:
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
            elif use_pct >= self.DISK_WARNING_PCT:
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
                        f"Alerta crítico em {self.DISK_CRITICAL_PCT}%."
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

    def _analyze_memory(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa uso de memória RAM e swap."""
        if not self._has_output(data.memory):
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

                    if use_pct >= self.MEM_CRITICAL_PCT:
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
                    elif use_pct >= self.MEM_WARNING_PCT:
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

    def _analyze_cpu_load(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa carga da CPU comparando com número de núcleos."""
        if not self._has_output(data.load_average) or not self._has_output(data.cpu_info):
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

            if load_ratio >= self.LOAD_CRITICAL_MULTIPLIER:
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
            elif load_ratio >= self.LOAD_WARNING_MULTIPLIER:
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

    def _analyze_temperature(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa temperatura do sistema via sensors e thermal_zones."""
        temps_found = []

        # Verifica saída de sensors (lm-sensors)
        if self._has_output(data.sensors):
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
        if self._has_output(data.vcgencmd_temp):
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

        if max_temp >= self.TEMP_CRITICAL_C:
            result.issues.append(Issue(
                severity=Severity.CRITICAL,
                category="Temperatura",
                title=f"Temperatura crítica: {max_temp:.1f}°C",
                description=(
                    f"Temperatura máxima detectada: {max_temp:.1f}°C. "
                    f"Threshold crítico: {self.TEMP_CRITICAL_C}°C. "
                    "Risco de throttling ou dano por superaquecimento."
                ),
                recommendation=(
                    "Verifique ventilação e dissipação de calor imediatamente. "
                    "Limpe poeira dos coolers. Verifique se o thermal paste está adequado. "
                    "Reduza carga do sistema se possível."
                ),
                raw_evidence=max_evidence,
            ))
        elif max_temp >= self.TEMP_WARNING_C:
            result.issues.append(Issue(
                severity=Severity.WARNING,
                category="Temperatura",
                title=f"Temperatura elevada: {max_temp:.1f}°C",
                description=(
                    f"Temperatura máxima: {max_temp:.1f}°C. "
                    f"Threshold de alerta: {self.TEMP_WARNING_C}°C."
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

    def _analyze_usb(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa dispositivos USB e erros relacionados."""
        usb_issues = []

        # Verifica erros USB no dmesg
        if self._has_output(data.usb_errors):
            errors = data.usb_errors.stdout
            if "over-current" in errors.lower() or "overcurrent" in errors.lower():
                usb_issues.append(Issue(
                    severity=Severity.CRITICAL,
                    category="USB",
                    title="Sobrecorrente USB detectada",
                    description=(
                        "O kernel detectou condição de sobrecorrente em porta USB. "
                        "Isso indica dispositivo com consumo excessivo de energia "
                        "ou possível dano à porta/hub."
                    ),
                    recommendation=(
                        "Desconecte dispositivos USB imediatamente. "
                        "Verifique danos físicos na porta. "
                        "Use hub USB com fonte de alimentação externa para dispositivos de alto consumo."
                    ),
                    raw_evidence=errors[:500],
                ))

            disconnect_count = len(re.findall(
                r"disconnect", errors, re.IGNORECASE))
            if disconnect_count > 5:
                usb_issues.append(Issue(
                    severity=Severity.WARNING,
                    category="USB",
                    title=f"Múltiplas desconexões USB ({disconnect_count} eventos)",
                    description=(
                        f"Detectadas {disconnect_count} desconexões USB nos logs do kernel. "
                        "Pode indicar cabo defeituoso, dispositivo com problema "
                        "ou instabilidade na fonte de alimentação."
                    ),
                    recommendation=(
                        "Troque cabos USB. Teste dispositivos em outra porta. "
                        "Verifique a fonte de alimentação (especialmente em Raspberry Pi)."
                    ),
                    raw_evidence=errors[:500],
                ))
            elif disconnect_count > 0:
                usb_issues.append(Issue(
                    severity=Severity.INFO,
                    category="USB",
                    title=f"Desconexões USB detectadas ({disconnect_count} evento(s))",
                    description=f"Ocorreram {disconnect_count} desconexões USB nos logs.",
                    recommendation="Monitore. Se recorrente, verifique cabos e dispositivos.",
                    raw_evidence=errors[:300],
                ))

        # Lista dispositivos USB conectados
        if self._has_output(data.lsusb):
            usb_count = len(data.lsusb.stdout.splitlines())
            result.issues.append(Issue(
                severity=Severity.INFO,
                category="USB",
                title=f"{usb_count} dispositivo(s) USB detectado(s)",
                description=data.lsusb.stdout[:500],
                recommendation="Verifique se todos os dispositivos esperados estão listados.",
            ))

        result.issues.extend(usb_issues)

    def _analyze_dmesg(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa o ring buffer do kernel (dmesg) em busca de erros críticos."""
        if not self._has_output(data.dmesg):
            return

        text = data.dmesg.stdout.lower()
        self._match_log_patterns(
            text=text,
            source="dmesg",
            result=result,
            raw_evidence=data.dmesg.stdout,
        )

    def _analyze_tty_overruns(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa input overruns em portas seriais (ttyS/ttyAMA) com contagem e período."""
        if not self._has_output(data.dmesg):
            return

        overrun_lines = [
            line for line in data.dmesg.stdout.splitlines()
            if re.search(r"tty.*input overrun", line, re.IGNORECASE)
        ]
        if not overrun_lines:
            return

        # Soma o total real de overruns (cada linha pode ter N > 1)
        total = 0
        devices: dict = {}
        for line in overrun_lines:
            m = re.search(r"(\d+)\s+input overrun", line)
            count = int(m.group(1)) if m else 1
            total += count
            dm = re.search(r"(tty\S+):\s+\d+\s+input overrun", line, re.IGNORECASE)
            dev = dm.group(1) if dm else "unknown"
            devices[dev] = devices.get(dev, 0) + count

        first_ts = re.sub(r"^\[(.+?)\].*", r"\1", overrun_lines[0]).strip()
        last_ts = re.sub(r"^\[(.+?)\].*", r"\1", overrun_lines[-1]).strip()
        device_summary = ", ".join(
            f"{dev} ({cnt} overruns)" for dev, cnt in sorted(devices.items())
        )

        # CRITICAL se >= 20 overruns totais, WARNING caso contrário
        severity = Severity.CRITICAL if total >= 20 else Severity.WARNING

        # Evidência: até 20 linhas + indicador de truncamento
        evidence = overrun_lines[:20]
        if len(overrun_lines) > 20:
            evidence.append(
                f"... ({len(overrun_lines) - 20} eventos adicionais omitidos)"
            )

        result.issues.append(Issue(
            severity=severity,
            category="Serial (tty)",
            title=(
                f"Input overruns em porta serial: {total} ocorrências "
                f"em {len(overrun_lines)} eventos"
            ),
            description=(
                f"{total} input overruns detectados em {len(overrun_lines)} eventos "
                f"nas porta(s) serial(is). "
                f"Dispositivo(s): {device_summary}. "
                f"Período: {first_ts} → {last_ts}. "
                f"Overruns indicam que o buffer de recepção da UART está transbordando: "
                f"a aplicação não consome os dados rápido o suficiente, "
                f"ou a taxa de baud rate está acima do suportado pelo hardware."
            ),
            recommendation=(
                "1. Verifique o baud rate configurado vs o do dispositivo conectado. "
                "2. Habilite controle de fluxo de hardware (RTS/CTS): "
                "stty -F /dev/ttyS0 crtscts. "
                "3. Aumente a prioridade do processo leitor da serial. "
                "4. Verifique o tipo de UART: setserial /dev/ttyS0 (usar 16550A ou superior). "
                f"5. Inspecione todos os eventos: dmesg -T | grep -i 'tty.*overrun'"
            ),
            raw_evidence="\n".join(evidence),
        ))

    def _analyze_usb_serial(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa erros em adaptadores USB-serial (ftdi_sio, cp210x, ch341, cdc_acm, pl2303)."""
        if not self._has_output(data.dmesg):
            return

        # Códigos errno que indicam falha crítica de comunicação
        CRITICAL_ERRNOS = {
            "-110": "ETIMEDOUT",
            "-19":  "ENODEV",
            "-32":  "EPIPE",
            "-104": "ECONNRESET",
            "-5":   "EIO",
        }
        USB_SERIAL_DRIVERS = r"ftdi_sio|cp210x|ch341|cdc_acm|pl2303"

        error_lines = [
            line for line in data.dmesg.stdout.splitlines()
            if re.search(USB_SERIAL_DRIVERS, line, re.IGNORECASE)
            and re.search(r"(fail|error|timeout|reset|disconnect)", line, re.IGNORECASE)
        ]
        if not error_lines:
            return

        # Classifica errno e coleta dispositivos afetados
        critical_found: list = []
        devices: set = set()
        for line in error_lines:
            m = re.search(r"(ttyUSB\d+|ttyACM\d+)", line, re.IGNORECASE)
            if m:
                devices.add(m.group(1))
            for errno, name in CRITICAL_ERRNOS.items():
                if errno in line:
                    critical_found.append(f"{errno} ({name})")
                    break

        n_total = len(error_lines)
        device_str = ", ".join(sorted(devices)) if devices else "desconhecido"
        severity = Severity.CRITICAL if critical_found else Severity.WARNING

        evidence = error_lines[:20]
        if len(error_lines) > 20:
            evidence.append(f"... ({len(error_lines) - 20} eventos adicionais omitidos)")

        errno_detail = ""
        if critical_found:
            unique_errnos = list(dict.fromkeys(critical_found))  # preserva ordem, remove dups
            errno_detail = f" Códigos de erro críticos detectados: {', '.join(unique_errnos)}."

        result.issues.append(Issue(
            severity=severity,
            category="Serial USB",
            title=f"Erros em adaptador USB-serial: {n_total} ocorrência(s) em {device_str}",
            description=(
                f"{n_total} erro(s) detectado(s) no(s) adaptador(es) USB-serial "
                f"(dispositivo(s): {device_str}).{errno_detail} "
                "Falhas como ETIMEDOUT (-110) indicam que o dispositivo USB não respondeu "
                "a tempo; ENODEV (-19) que foi desconectado inesperadamente."
            ),
            recommendation=(
                "1. Verifique a conexão física do adaptador USB-serial. "
                "2. Troque o cabo USB e teste em outra porta. "
                "3. Em Raspberry Pi, verifique a alimentação (USB-serial falha com baixa tensão). "
                "4. Certifique-se de que o driver correto está carregado: lsmod | grep ftdi_sio. "
                f"5. Consulte todos os eventos: dmesg -T | grep -iE '{USB_SERIAL_DRIVERS}'"
            ),
            raw_evidence="\n".join(evidence),
        ))

    def _analyze_journalctl(self, data: SystemData, result: DiagnosticResult) -> None:
        """Analisa erros do journalctl (systemd journal)."""
        if not self._has_output(data.journalctl_errors):
            return

        text = data.journalctl_errors.stdout.lower()
        self._match_log_patterns(
            text=text,
            source="journalctl",
            result=result,
            raw_evidence=data.journalctl_errors.stdout,
        )

    def _match_log_patterns(
        self,
        text: str,
        source: str,
        result: DiagnosticResult,
        raw_evidence: str,
    ) -> None:
        """
        Verifica padrões de erro em texto de log.

        Args:
            text: Texto do log (lowercase).
            source: Nome da fonte (para título).
            result: Objeto DiagnosticResult para adicionar issues.
            raw_evidence: Texto original para evidência.
        """
        for pattern in self.CRITICAL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                result.issues.append(Issue(
                    severity=Severity.CRITICAL,
                    category=f"Log ({source})",
                    title=f"Erro crítico detectado: '{pattern}'",
                    description=(
                        f"Padrão de erro crítico encontrado em {source}: '{pattern}'. "
                        f"Ocorrências: {len(matches)}."
                    ),
                    recommendation=(
                        "Investigue os logs completos para determinar a causa raiz. "
                        f"Execute manualmente: dmesg -T | grep -i '{pattern}'"
                    ),
                    raw_evidence=self._extract_matching_lines(
                        raw_evidence, pattern, max_lines=20)[:1500],
                ))

        for pattern in self.WARNING_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                result.issues.append(Issue(
                    severity=Severity.WARNING,
                    category=f"Log ({source})",
                    title=f"Aviso detectado: '{pattern}'",
                    description=(
                        f"Padrão de aviso encontrado em {source}: '{pattern}'. "
                        f"Ocorrências: {len(matches)}."
                    ),
                    recommendation=(
                        f"Verifique o contexto completo. "
                        f"Execute: journalctl -p 3 -xb | grep -i '{pattern}'"
                    ),
                    raw_evidence=self._extract_matching_lines(
                        raw_evidence, pattern, max_lines=20)[:1500],
                ))

    def _analyze_failed_services(self, data: SystemData, result: DiagnosticResult) -> None:
        """Verifica serviços systemd com falha."""
        if not self._has_output(data.failed_services):
            return

        text = data.failed_services.stdout
        # Procura por serviços marcados como "failed" no systemctl
        failed = re.findall(r"(\S+\.service)\s+.*failed", text, re.IGNORECASE)

        if failed:
            for svc in failed:
                result.issues.append(Issue(
                    severity=Severity.WARNING,
                    category="Serviços",
                    title=f"Serviço com falha: {svc}",
                    description=f"O serviço systemd '{svc}' está em estado 'failed'.",
                    recommendation=(
                        f"Verifique o log: 'journalctl -u {svc} -n 50'. "
                        f"Tente reiniciar: 'sudo systemctl restart {svc}'."
                    ),
                    raw_evidence=text[:400],
                ))
        elif "0 loaded units listed" not in text and text.strip():
            result.issues.append(Issue(
                severity=Severity.INFO,
                category="Serviços",
                title="Nenhum serviço com falha detectado",
                description="Todos os serviços systemd estão funcionando normalmente.",
                recommendation="Sem ação necessária.",
            ))

    # ------------------------------------------------------------------ #
    # Métodos auxiliares
    # ------------------------------------------------------------------ #

    def _safe_output(self, result: Optional[CommandResult]) -> str:
        """Retorna stdout de forma segura, sem exceções."""
        if result and result.stdout:
            return result.stdout.strip()[:200]
        return "não disponível"

    def _has_output(self, result: Optional[CommandResult]) -> bool:
        """Verifica se um CommandResult tem saída útil."""
        return (
            result is not None
            and bool(result.stdout)
            and len(result.stdout.strip()) > 0
        )

    def _extract_matching_lines(self, text: str, pattern: str, max_lines: int = 10) -> str:
        """Extrai linhas que contêm o padrão para usar como evidência."""
        matches = []
        for line in text.splitlines():
            if re.search(pattern, line, re.IGNORECASE):
                matches.append(line)
                if len(matches) >= max_lines:
                    break
        return "\n".join(matches)

    def _parse_os_info(self, result: Optional[CommandResult]) -> str:
        """Extrai nome legível do SO a partir de /etc/os-release."""
        if not self._has_output(result):
            return "desconhecido"

        for line in result.stdout.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')

        return result.stdout.splitlines()[0][:100]

    def _generate_summary(self, result: DiagnosticResult) -> str:
        """Gera texto de resumo executivo."""
        n_crit = len(result.critical_issues)
        n_warn = len(result.warning_issues)
        n_info = len(result.info_issues)

        if n_crit > 0:
            action = (
                f"AÇÃO IMEDIATA NECESSÁRIA: {n_crit} problema(s) crítico(s) identificado(s). "
                "Intervenção manual urgente é recomendada."
            )
        elif n_warn > 0:
            action = (
                f"Atenção requerida: {n_warn} aviso(s) identificado(s). "
                "Verifique as recomendações e monitore o sistema."
            )
        else:
            action = "Sistema parece saudável. Sem problemas críticos ou avisos identificados."

        return (
            f"Sistema '{result.hostname}' analisado. "
            f"Saúde geral: {result.overall_health}. "
            f"{action} "
            f"Total de observações: {n_crit} crítico(s), {n_warn} aviso(s), {n_info} informação(ões)."
        )
