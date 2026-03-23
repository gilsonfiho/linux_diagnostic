"""
Testes para ReportGenerator
==============================
Valida geração de relatórios Markdown e PDF.
"""

import pytest
import tempfile
from pathlib import Path

from src.collector.system_collector import SystemData, CommandResult
from src.analyzer.diagnostic_analyzer import DiagnosticAnalyzer, DiagnosticResult, Severity, Issue
from src.reporter.report_generator import ReportGenerator
from mock_ssh_client import MockSSHClient


def make_result(stdout: str) -> CommandResult:
    return CommandResult(command="mock", stdout=stdout, stderr="", exit_code=0, success=True)


def make_sample_result() -> DiagnosticResult:
    """Cria DiagnosticResult de exemplo com issues de todos os níveis."""
    result = DiagnosticResult()
    result.hostname = "testserver"
    result.os_info = "Ubuntu 22.04.3 LTS"
    result.kernel = "Linux testserver 5.15.0-91-generic x86_64"
    result.uptime = "up 7 days, 3:42, 2 users, load average: 0.45, 0.52, 0.48"
    result.issues = [
        Issue(
            severity=Severity.CRITICAL,
            category="Armazenamento",
            title="Disco crítico: / com 97% de uso",
            description="O ponto de montagem '/' está com 97% de uso.",
            recommendation="Ação imediata: libere espaço em disco.",
            raw_evidence="/dev/sda1  50G 48G 1.5G 97% /",
        ),
        Issue(
            severity=Severity.WARNING,
            category="Memória",
            title="Memória alta: 87% em uso",
            description="RAM: 6800MB usados de 7850MB total.",
            recommendation="Monitore o consumo de memória.",
            raw_evidence="Mem: 7850 6800 150 200 900 720",
        ),
        Issue(
            severity=Severity.INFO,
            category="CPU",
            title="Carga normal: 0.52 (4 CPUs)",
            description="Load average: 1m=0.45, 5m=0.52, 15m=0.48",
            recommendation="Sem ação necessária.",
        ),
    ]
    result.summary = (
        "Sistema 'testserver' analisado. Saúde geral: CRÍTICO. "
        "AÇÃO IMEDIATA NECESSÁRIA: 1 problema(s) crítico(s)."
    )
    return result


def make_sample_system_data() -> SystemData:
    data = SystemData()
    data.hostname = make_result("testserver")
    data.os_info = make_result('PRETTY_NAME="Ubuntu 22.04.3 LTS"\n')
    data.kernel = make_result("Linux testserver 5.15.0-91-generic x86_64")
    data.uptime = make_result("up 7 days, load average: 0.45")
    data.memory = make_result(
        "               total        used        free\nMem:            7850        3012        2341\nSwap:           2048           0        2048\n"
    )
    data.disk_usage = make_result(
        "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1  50G 18G 30G 37% /\n"
    )
    data.cpu_info = make_result("4\nmodel name: Intel Core i5")
    data.load_average = make_result("0.45 0.52 0.48 2/342 12345")
    data.sensors = make_result("Package id 0:  +42.0°C\n")
    data.failed_services = make_result("0 loaded units listed.\n")
    return data


CONN_INFO = {"host": "192.168.1.100", "port": 22, "user": "pi"}


@pytest.fixture
def tmp_output(tmp_path):
    """Diretório temporário para saída de relatórios."""
    return tmp_path


@pytest.fixture
def generator(tmp_output):
    return ReportGenerator(output_dir=tmp_output, report_name="test_report")


@pytest.fixture
def sample_result():
    return make_sample_result()


@pytest.fixture
def sample_data():
    return make_sample_system_data()


class TestReportGeneratorInit:
    """Testa inicialização do ReportGenerator."""

    def test_creates_output_dir(self, tmp_path):
        new_dir = tmp_path / "new_subdir" / "reports"
        assert not new_dir.exists()
        ReportGenerator(output_dir=new_dir, report_name="test")
        assert new_dir.exists()

    def test_stores_report_name(self, tmp_output):
        gen = ReportGenerator(output_dir=tmp_output, report_name="my_report")
        assert gen.report_name == "my_report"


class TestMarkdownGeneration:
    """Testa geração de relatório Markdown."""

    def test_generates_markdown_file(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        assert len(files) == 1
        assert files[0].suffix == ".md"
        assert files[0].exists()

    def test_markdown_content_has_hostname(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "testserver" in content

    def test_markdown_has_critical_section(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "Problemas Críticos" in content or "CRÍTICO" in content

    def test_markdown_has_connection_info(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_markdown_has_summary(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "Resumo Executivo" in content

    def test_markdown_has_all_severity_sections(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        # Verifica que seções de todas as severidades estão presentes
        assert "Críticos" in content or "CRÍTICO" in content
        assert "Avisos" in content or "AVISO" in content
        assert "Informações" in content or "INFO" in content

    def test_markdown_has_raw_data_section(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "Dados Técnicos" in content

    def test_markdown_utf8_encoding(self, generator, sample_result, sample_data):
        """Arquivo deve ser salvo em UTF-8 sem erros."""
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        # Não deve lançar exceção ao ler como UTF-8
        content = files[0].read_text(encoding="utf-8")
        assert len(content) > 0

    def test_markdown_only_generates_one_file(self, generator, sample_result, sample_data):
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        assert len(files) == 1

    def test_issue_recommendation_in_report(self, generator, sample_result, sample_data):
        """Recomendações dos issues devem aparecer no relatório."""
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        content = files[0].read_text(encoding="utf-8")
        assert "Ação imediata" in content


class TestPDFGeneration:
    """Testa geração de PDF."""

    def test_pdf_generation_or_graceful_skip(self, generator, sample_result, sample_data):
        """PDF deve ser gerado (se fpdf2 instalado) ou ignorado silenciosamente."""
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="pdf",
        )
        # Se fpdf2 não instalado: retorna lista vazia (sem crash)
        # Se fpdf2 instalado: retorna [pdf_path]
        assert isinstance(files, list)
        if files:
            assert files[0].suffix == ".pdf"

    def test_both_format_always_returns_markdown(self, generator, sample_result, sample_data):
        """Formato 'both' sempre gera pelo menos o Markdown."""
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="both",
        )
        md_files = [f for f in files if f.suffix == ".md"]
        assert len(md_files) == 1

    def test_pdf_format_no_crash_without_markdown(self, generator, sample_result, sample_data):
        """Formato 'pdf' não deve gerar arquivo .md."""
        files = generator.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="pdf",
        )
        md_files = [f for f in files if f.suffix == ".md"]
        assert len(md_files) == 0


class TestReportContent:
    """Testa conteúdo detalhado do relatório."""

    def test_empty_issues_report(self, generator, tmp_output):
        """Relatório sem issues deve ser gerado sem erros."""
        empty_result = DiagnosticResult()
        empty_result.hostname = "empty-server"
        empty_result.summary = "Sistema sem issues."
        files = generator.generate(
            diagnostic_result=empty_result,
            system_data=make_sample_system_data(),
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        assert len(files) == 1
        content = files[0].read_text(encoding="utf-8")
        assert "empty-server" in content

    def test_report_name_in_filename(self, tmp_output, sample_result, sample_data):
        gen = ReportGenerator(output_dir=tmp_output, report_name="custom_report_name")
        files = gen.generate(
            diagnostic_result=sample_result,
            system_data=sample_data,
            connection_info=CONN_INFO,
            output_format="markdown",
        )
        assert files[0].name == "custom_report_name.md"


class TestEndToEnd:
    """
    Teste E2E completo: MockSSH → SystemCollector → DiagnosticAnalyzer → ReportGenerator.
    Simula o fluxo completo do main.py sem conexão SSH real.
    """

    def test_full_pipeline_normal_scenario(self, tmp_output):
        from src.collector.system_collector import SystemCollector

        mock = MockSSHClient("normal")
        collector = SystemCollector(ssh_client=mock, is_raspberry_pi=False)
        system_data = collector.collect_all()

        analyzer = DiagnosticAnalyzer()
        result = analyzer.analyze(system_data)

        gen = ReportGenerator(output_dir=tmp_output, report_name="e2e_normal")
        files = gen.generate(
            diagnostic_result=result,
            system_data=system_data,
            connection_info={"host": "mock-server", "port": 22, "user": "pi"},
            output_format="markdown",
        )

        assert len(files) == 1
        content = files[0].read_text(encoding="utf-8")
        assert "server01" in content
        assert len(result.issues) > 0

    def test_full_pipeline_critical_scenario(self, tmp_output):
        from src.collector.system_collector import SystemCollector

        mock = MockSSHClient("critical")
        collector = SystemCollector(ssh_client=mock, is_raspberry_pi=False)
        system_data = collector.collect_all()

        analyzer = DiagnosticAnalyzer()
        result = analyzer.analyze(system_data)

        gen = ReportGenerator(output_dir=tmp_output, report_name="e2e_critical")
        files = gen.generate(
            diagnostic_result=result,
            system_data=system_data,
            connection_info={"host": "mock-server", "port": 22, "user": "root"},
            output_format="markdown",
        )

        assert len(files) == 1
        # Cenário crítico deve gerar problemas críticos
        assert len(result.critical_issues) > 0
        assert result.overall_health == "CRÍTICO"

    def test_full_pipeline_warnings_scenario(self, tmp_output):
        from src.collector.system_collector import SystemCollector

        mock = MockSSHClient("warnings")
        collector = SystemCollector(ssh_client=mock, is_raspberry_pi=False)
        system_data = collector.collect_all()

        analyzer = DiagnosticAnalyzer()
        result = analyzer.analyze(system_data)

        gen = ReportGenerator(output_dir=tmp_output, report_name="e2e_warnings")
        files = gen.generate(
            diagnostic_result=result,
            system_data=system_data,
            connection_info={"host": "mock-server", "port": 22, "user": "admin"},
            output_format="markdown",
        )

        assert len(files) == 1
        # Cenário de avisos deve ter pelo menos alguns issues
        assert len(result.issues) > 0
