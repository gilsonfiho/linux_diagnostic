"""
Report Generator
=================
Módulo responsável pela geração de relatórios diagnósticos.
Suporta saída em Markdown e PDF.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from src.analyzer.diagnostic_analyzer import DiagnosticResult, Severity, Issue
from src.collector.system_collector import SystemData

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Gera relatórios diagnósticos a partir dos resultados da análise.

    Formatos suportados:
    - Markdown (.md)
    - PDF (.pdf) via markdown + WeasyPrint ou fpdf2
    """

    # Emojis para representar severidade visualmente no Markdown
    SEVERITY_ICONS = {
        Severity.CRITICAL: "🔴",
        Severity.WARNING: "🟡",
        Severity.INFO: "🟢",
    }

    def __init__(self, output_dir: Path, report_name: str):
        """
        Inicializa o gerador de relatórios.

        Args:
            output_dir: Diretório onde os relatórios serão salvos.
            report_name: Nome base dos arquivos (sem extensão).
        """
        self.output_dir = Path(output_dir)
        self.report_name = report_name
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        diagnostic_result: DiagnosticResult,
        system_data: SystemData,
        connection_info: Dict[str, str],
        output_format: str = "both",
    ) -> List[Path]:
        """
        Gera os relatórios nos formatos solicitados.

        Args:
            diagnostic_result: Resultado da análise diagnóstica.
            system_data: Dados brutos coletados.
            connection_info: Informações da conexão SSH.
            output_format: "markdown", "pdf" ou "both".

        Returns:
            Lista de caminhos dos arquivos gerados.
        """
        generated = []

        markdown_content = self._build_markdown(
            diagnostic_result, system_data, connection_info
        )

        # Sempre gera Markdown primeiro (base para PDF)
        if output_format in ("markdown", "both"):
            md_path = self.output_dir / f"{self.report_name}.md"
            md_path.write_text(markdown_content, encoding="utf-8")
            generated.append(md_path)
            logger.info(f"Relatório Markdown gerado: {md_path}")

        if output_format in ("pdf", "both"):
            pdf_path = self._generate_pdf(markdown_content)
            if pdf_path:
                generated.append(pdf_path)

        return generated

    def _build_markdown(
        self,
        result: DiagnosticResult,
        data: SystemData,
        conn_info: Dict[str, str],
    ) -> str:
        """
        Constrói o conteúdo completo do relatório em Markdown.

        Args:
            result: Resultado diagnóstico.
            data: Dados brutos do sistema.
            conn_info: Dados de conexão.

        Returns:
            String com o conteúdo Markdown.
        """
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        sections = []

        # ---- Cabeçalho ----
        sections.append(f"# 🖥️ Relatório de Diagnóstico Linux")
        sections.append(f"\n**Gerado em:** {now}  ")
        sections.append(f"**Host:** `{conn_info.get('host', 'N/A')}:{conn_info.get('port', 22)}`  ")
        sections.append(f"**Usuário:** `{conn_info.get('user', 'N/A')}`  ")
        sections.append(f"**Hostname:** `{result.hostname}`  ")
        sections.append(f"**Sistema:** {result.os_info}  ")
        sections.append(f"**Kernel:** `{result.kernel}`  ")
        sections.append(f"**Uptime:** {result.uptime}  ")
        sections.append(f"**Saúde Geral:** {self._health_badge(result.overall_health)}")

        # ---- Resumo Executivo ----
        sections.append("\n---\n")
        sections.append("## 📋 Resumo Executivo\n")
        sections.append(f"> {result.summary}\n")

        # Tabela de contagem
        sections.append("### Contagem de Ocorrências\n")
        sections.append("| Severidade | Quantidade |")
        sections.append("|------------|------------|")
        sections.append(f"| 🔴 CRÍTICO  | {len(result.critical_issues)} |")
        sections.append(f"| 🟡 AVISO    | {len(result.warning_issues)} |")
        sections.append(f"| 🟢 INFO     | {len(result.info_issues)} |")
        sections.append(f"| **Total**  | **{len(result.issues)}** |")

        # ---- Problemas Críticos ----
        if result.critical_issues:
            sections.append("\n---\n")
            sections.append("## 🔴 Problemas Críticos\n")
            for issue in result.critical_issues:
                sections.append(self._format_issue(issue))

        # ---- Avisos ----
        if result.warning_issues:
            sections.append("\n---\n")
            sections.append("## 🟡 Avisos\n")
            for issue in result.warning_issues:
                sections.append(self._format_issue(issue))

        # ---- Informações ----
        if result.info_issues:
            sections.append("\n---\n")
            sections.append("## 🟢 Informações\n")
            for issue in result.info_issues:
                sections.append(self._format_issue(issue, show_evidence=False))

        # ---- Dados Técnicos Brutos ----
        sections.append("\n---\n")
        sections.append("## 🔧 Dados Técnicos Coletados\n")
        sections.append(self._format_raw_data(data))

        # ---- Rodapé ----
        sections.append("\n---\n")
        sections.append(
            f"*Relatório gerado automaticamente pelo Linux SSH Diagnostics v1.0.0 — {now}*"
        )

        return "\n".join(sections)

    def _format_issue(self, issue: Issue, show_evidence: bool = True) -> str:
        """Formata um Issue individual para Markdown."""
        icon = self.SEVERITY_ICONS.get(issue.severity, "⚪")
        lines = [
            f"### {icon} {issue.title}",
            f"\n**Categoria:** {issue.category}  ",
            f"**Severidade:** `{issue.severity.value}`\n",
            f"**Descrição:** {issue.description}\n",
            f"**Recomendação:** {issue.recommendation}\n",
        ]

        if show_evidence and issue.raw_evidence:
            # Trunca evidência para não sobrecarregar o relatório
            evidence = issue.raw_evidence[:600]
            if len(issue.raw_evidence) > 600:
                evidence += "\n... (truncado)"
            lines.append(f"**Evidência:**\n```\n{evidence}\n```\n")

        return "\n".join(lines)

    def _format_raw_data(self, data: SystemData) -> str:
        """Formata os dados brutos coletados como seção técnica."""
        sections = []

        raw_sections = [
            ("Informações do Sistema", [data.hostname, data.os_info, data.kernel]),
            ("Uptime e Carga", [data.uptime, data.load_average]),
            ("CPU", [data.cpu_info, data.top]),
            ("Memória", [data.memory]),
            ("Disco", [data.disk_usage, data.block_devices]),
            ("Temperatura", [data.sensors, data.vcgencmd_temp]),
            ("Dispositivos USB", [data.lsusb]),
            ("Interfaces de Rede", [data.network_interfaces]),
            ("Serviços com Falha", [data.failed_services]),
            ("Erros USB (dmesg)", [data.usb_errors]),
            ("Processos (Top)", [data.top_processes]),
        ]

        for section_title, results in raw_sections:
            combined_output = []
            for r in results:
                if r and r.stdout:
                    combined_output.append(r.stdout[:800])
            if combined_output:
                sections.append(f"### {section_title}\n")
                sections.append(f"```\n{chr(10).join(combined_output)}\n```\n")

        return "\n".join(sections)

    def _health_badge(self, health: str) -> str:
        """Retorna badge de saúde formatado."""
        badges = {
            "CRÍTICO": "🔴 **CRÍTICO**",
            "ATENÇÃO": "🟡 **ATENÇÃO**",
            "SAUDÁVEL": "🟢 **SAUDÁVEL**",
        }
        return badges.get(health, f"⚪ {health}")

    def _generate_pdf(self, markdown_content: str) -> Optional[Path]:
        """
        Gera PDF a partir do conteúdo Markdown.

        Tenta usar fpdf2 para geração do PDF.
        Retorna None se nenhuma biblioteca estiver disponível.
        """
        pdf_path = self.output_dir / f"{self.report_name}.pdf"

        try:
            from src.reporter.pdf_renderer import render_pdf_with_fpdf
            render_pdf_with_fpdf(markdown_content, pdf_path)
            logger.info(f"Relatório PDF gerado: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning(
                "fpdf2 não instalado. Instale com: pip install fpdf2. "
                "Somente o Markdown foi gerado."
            )
            return None
        except Exception as e:
            logger.error(f"Falha ao gerar PDF: {e}")
            return None
