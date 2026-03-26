"""
Device Analyzers
================
Analisadores de dispositivos conectados: USB, portas seriais (ttyS/ttyAMA)
e adaptadores USB-serial (ftdi_sio, cp210x, ch341, cdc_acm, pl2303).
"""

import logging
import re

from src.collector.system_collector import SystemData
from src.analyzer.models import Severity, Issue, DiagnosticResult, _has_output

logger = logging.getLogger(__name__)

# Drivers USB-serial monitorados
_USB_SERIAL_DRIVERS = r"ftdi_sio|cp210x|ch341|cdc_acm|pl2303"

# Códigos errno que indicam falha crítica de comunicação
_CRITICAL_ERRNOS = {
    "-110": "ETIMEDOUT",
    "-19":  "ENODEV",
    "-32":  "EPIPE",
    "-104": "ECONNRESET",
    "-5":   "EIO",
}


def analyze_usb(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa dispositivos USB e erros relacionados."""
    usb_issues = []

    # Verifica erros USB no dmesg
    if _has_output(data.usb_errors):
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

        disconnect_count = len(re.findall(r"disconnect", errors, re.IGNORECASE))
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
    if _has_output(data.lsusb):
        usb_count = len(data.lsusb.stdout.splitlines())
        result.issues.append(Issue(
            severity=Severity.INFO,
            category="USB",
            title=f"{usb_count} dispositivo(s) USB detectado(s)",
            description=data.lsusb.stdout[:500],
            recommendation="Verifique se todos os dispositivos esperados estão listados.",
        ))

    result.issues.extend(usb_issues)


def analyze_tty_overruns(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa input overruns em portas seriais (ttyS/ttyAMA) com contagem e período."""
    if not _has_output(data.dmesg):
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
        evidence.append(f"... ({len(overrun_lines) - 20} eventos adicionais omitidos)")

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


def analyze_usb_serial(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa erros em adaptadores USB-serial (ftdi_sio, cp210x, ch341, cdc_acm, pl2303)."""
    if not _has_output(data.dmesg):
        return

    error_lines = [
        line for line in data.dmesg.stdout.splitlines()
        if re.search(_USB_SERIAL_DRIVERS, line, re.IGNORECASE)
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
        for errno, name in _CRITICAL_ERRNOS.items():
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
            f"5. Consulte todos os eventos: dmesg -T | grep -iE '{_USB_SERIAL_DRIVERS}'"
        ),
        raw_evidence="\n".join(evidence),
    ))
