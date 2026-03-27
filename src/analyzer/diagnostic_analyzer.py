"""
Diagnostic Analyzer
====================
Orquestrador da análise diagnóstica. Coordena os analisadores de domínio
e produz um DiagnosticResult completo a partir de um SystemData coletado.

Importações de compatibilidade:
  Severity, Issue e DiagnosticResult são re-exportados deste módulo para
  que nenhum consumidor externo precise alterar seus imports.
"""

import logging
from typing import Optional

from src.collector.system_collector import SystemData, CommandResult

# Re-exporta os tipos públicos — mantém compatibilidade com todos os imports existentes
from src.analyzer.models import Severity, Issue, DiagnosticResult  # noqa: F401
from src.analyzer.models import _has_output, _safe_output

from src.analyzer.hardware import (
    analyze_disk,
    analyze_memory,
    analyze_cpu_load,
    analyze_temperature,
)
from src.analyzer.devices import (
    analyze_usb,
    analyze_tty_overruns,
    analyze_usb_serial,
)
from src.analyzer.logs import (
    analyze_dmesg,
    analyze_journalctl,
    analyze_failed_services,
)
from src.analyzer.network import (
    analyze_arp,
    analyze_network_interface_errors,
    analyze_network_link_events,
    analyze_gateway_connectivity,
)

logger = logging.getLogger(__name__)


class DiagnosticAnalyzer:
    """
    Coordena a análise completa do sistema delegando para analisadores de domínio.

    Cada analisador de domínio (hardware, devices, logs) é uma função pura que
    recebe SystemData e DiagnosticResult e adiciona Issues ao resultado.
    """

    def analyze(self, data: SystemData) -> DiagnosticResult:
        """
        Executa a análise completa dos dados coletados.

        Args:
            data: Dados coletados pelo SystemCollector.

        Returns:
            DiagnosticResult com todos os problemas encontrados, ordenado por severidade.
        """
        result = DiagnosticResult()

        # Extrai informações básicas do sistema
        result.hostname = _safe_output(data.hostname)
        result.os_info = _parse_os_info(data.os_info)
        result.kernel = _safe_output(data.kernel)
        result.uptime = _safe_output(data.uptime)

        logger.debug("Analisando: disco...")
        analyze_disk(data, result)

        logger.debug("Analisando: memória...")
        analyze_memory(data, result)

        logger.debug("Analisando: CPU/carga...")
        analyze_cpu_load(data, result)

        logger.debug("Analisando: temperatura...")
        analyze_temperature(data, result)

        logger.debug("Analisando: USB...")
        analyze_usb(data, result)

        logger.debug("Analisando: logs do sistema...")
        analyze_dmesg(data, result)

        logger.debug("Analisando: overruns em portas seriais...")
        analyze_tty_overruns(data, result)

        logger.debug("Analisando: erros em adaptadores USB-serial...")
        analyze_usb_serial(data, result)

        logger.debug("Analisando: erros críticos (journalctl)...")
        analyze_journalctl(data, result)

        logger.debug("Analisando: serviços com falha...")
        analyze_failed_services(data, result)

        logger.debug("Analisando: ARP e conectividade de rede...")
        analyze_arp(data, result)

        logger.debug("Analisando: erros de interface de rede...")
        analyze_network_interface_errors(data, result)

        logger.debug("Analisando: eventos de link (flapping)...")
        analyze_network_link_events(data, result)

        logger.debug("Analisando: conectividade com gateway...")
        analyze_gateway_connectivity(data, result)

        result.summary = _generate_summary(result)

        # Ordena por severidade: CRITICAL > WARNING > INFO
        severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        result.issues.sort(key=lambda x: severity_order[x.severity])

        logger.info(
            f"Análise concluída: {len(result.critical_issues)} crítico(s), "
            f"{len(result.warning_issues)} aviso(s), "
            f"{len(result.info_issues)} info(s)"
        )

        return result


# ------------------------------------------------------------------ #
# Helpers do orquestrador
# ------------------------------------------------------------------ #

def _parse_os_info(result: Optional[CommandResult]) -> str:
    """Extrai nome legível do SO a partir de /etc/os-release."""
    if not _has_output(result):
        return "desconhecido"

    for line in result.stdout.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')

    return result.stdout.splitlines()[0][:100]


def _generate_summary(result: DiagnosticResult) -> str:
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
