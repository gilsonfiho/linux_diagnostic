"""
Log Analyzers
=============
Analisadores de logs do kernel (dmesg), journal do sistema (journalctl)
e serviços com falha (systemd). Inclui os padrões de erro monitorados.
"""

import logging
import re

from src.collector.system_collector import SystemData
from src.analyzer.models import Severity, Issue, DiagnosticResult, _has_output

logger = logging.getLogger(__name__)

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


def analyze_dmesg(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa o ring buffer do kernel (dmesg) em busca de erros críticos."""
    if not _has_output(data.dmesg):
        return

    _match_log_patterns(
        text=data.dmesg.stdout.lower(),
        source="dmesg",
        result=result,
        raw_evidence=data.dmesg.stdout,
    )


def analyze_journalctl(data: SystemData, result: DiagnosticResult) -> None:
    """Analisa erros do journalctl (systemd journal)."""
    if not _has_output(data.journalctl_errors):
        return

    _match_log_patterns(
        text=data.journalctl_errors.stdout.lower(),
        source="journalctl",
        result=result,
        raw_evidence=data.journalctl_errors.stdout,
    )


def analyze_failed_services(data: SystemData, result: DiagnosticResult) -> None:
    """Verifica serviços systemd com falha."""
    if not _has_output(data.failed_services):
        return

    text = data.failed_services.stdout
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
# Helpers internos
# ------------------------------------------------------------------ #

def _match_log_patterns(
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
    for pattern in CRITICAL_PATTERNS:
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
                raw_evidence=_extract_matching_lines(raw_evidence, pattern, max_lines=20)[:1500],
            ))

    for pattern in WARNING_PATTERNS:
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
                raw_evidence=_extract_matching_lines(raw_evidence, pattern, max_lines=20)[:1500],
            ))


def _extract_matching_lines(text: str, pattern: str, max_lines: int = 10) -> str:
    """Extrai linhas que contêm o padrão para usar como evidência."""
    matches = []
    for line in text.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            matches.append(line)
            if len(matches) >= max_lines:
                break
    return "\n".join(matches)
