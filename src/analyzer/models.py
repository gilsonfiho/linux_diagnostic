"""
Models
======
Tipos de dados centrais do diagnóstico: Severity, Issue, DiagnosticResult.
Inclui utilitários de acesso a CommandResult usados por todos os analisadores.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from src.collector.system_collector import CommandResult


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


# ------------------------------------------------------------------ #
# Utilitários de acesso a CommandResult
# ------------------------------------------------------------------ #

def _has_output(result: Optional[CommandResult]) -> bool:
    """Verifica se um CommandResult tem saída útil."""
    return (
        result is not None
        and bool(result.stdout)
        and len(result.stdout.strip()) > 0
    )


def _safe_output(result: Optional[CommandResult]) -> str:
    """Retorna stdout de forma segura, sem exceções."""
    if result and result.stdout:
        return result.stdout.strip()[:200]
    return "não disponível"
