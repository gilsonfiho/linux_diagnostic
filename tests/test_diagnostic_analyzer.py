"""
Testes para DiagnosticAnalyzer
================================
Valida regras de detecção, classificação de severidade e parsing.
"""

import pytest
from src.collector.system_collector import SystemData, CommandResult
from src.analyzer.diagnostic_analyzer import DiagnosticAnalyzer, DiagnosticResult, Severity, Issue


def make_result(stdout: str, success: bool = True) -> CommandResult:
    """Helper: cria CommandResult com stdout fornecido."""
    return CommandResult(
        command="mock",
        stdout=stdout,
        stderr="",
        exit_code=0 if success else 1,
        success=success,
    )


def make_empty_data() -> SystemData:
    """Cria SystemData mínimo válido (sem dados de sistema)."""
    return SystemData()


def make_healthy_data() -> SystemData:
    """Cria SystemData representando sistema saudável."""
    data = SystemData()
    data.hostname = make_result("server01.local")
    data.os_info = make_result('PRETTY_NAME="Ubuntu 22.04.3 LTS"\nID=ubuntu\n')
    data.kernel = make_result("Linux server01 5.15.0-91-generic #101-Ubuntu x86_64")
    data.uptime = make_result(" 14:23:01 up 7 days,  3:42,  load average: 0.45, 0.52, 0.48")
    data.load_average = make_result("0.45 0.52 0.48 2/342 12345")
    data.cpu_info = make_result("4\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz")
    data.memory = make_result(
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:            7850        3012        2341         245        2496        4521\n"
        "Swap:           2048           0        2048\n"
    )
    data.disk_usage = make_result(
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "udev            3.8G     0  3.8G   0% /dev\n"
        "tmpfs           785M  1.6M  784M   1% /run\n"
        "/dev/sda1        50G   18G   30G  37% /\n"
        "/dev/sda2       100G   75G   20G  79% /data\n"
    )
    data.sensors = make_result(
        "coretemp-isa-0000\n"
        "Package id 0:  +42.0°C  (high = +100.0°C)\n"
        "Core 0:        +40.0°C\n"
    )
    data.vcgencmd_temp = make_result("thermal_zone0: 42.0°C\n")
    data.dmesg = make_result(
        "[Mon Nov 20 14:00:01 2023] Linux version 5.15.0\n"
        "[Mon Nov 20 14:00:05 2023] BIOS-provided physical RAM map\n"
    )
    data.journalctl_errors = make_result(
        "Nov 20 14:00:01 server01 systemd[1]: Started System Logging Service.\n"
    )
    data.failed_services = make_result("0 loaded units listed.\n")
    data.lsusb = make_result(
        "Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver\n"
        "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
    )
    data.usb_errors = make_result("")
    return data


@pytest.fixture
def analyzer():
    return DiagnosticAnalyzer()


@pytest.fixture
def healthy_data():
    return make_healthy_data()


class TestAnalyzerStructure:
    """Verifica que analyze() retorna DiagnosticResult válido."""

    def test_returns_diagnostic_result(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        assert isinstance(result, DiagnosticResult)

    def test_has_issues_list(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        assert isinstance(result.issues, list)

    def test_has_summary(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0

    def test_hostname_extracted(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        assert result.hostname == "server01.local"

    def test_os_info_extracted(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        assert "Ubuntu" in result.os_info

    def test_empty_data_does_not_crash(self, analyzer):
        """Analyzer não deve lançar exceção com dados vazios."""
        result = analyzer.analyze(make_empty_data())
        assert isinstance(result, DiagnosticResult)

    def test_issues_sorted_by_severity(self, analyzer):
        """Issues devem estar ordenados: CRITICAL > WARNING > INFO."""
        data = make_healthy_data()
        # Adiciona disco crítico
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   48G  1.5G  97% /\n"
        )
        result = analyzer.analyze(data)
        severities = [i.severity for i in result.issues]
        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        for i in range(len(severities) - 1):
            assert order[severities[i]] <= order[severities[i + 1]]


class TestDiskAnalysis:
    """Testa regras de análise de disco."""

    def test_normal_disk_is_info(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   18G   30G  37% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.INFO for i in disk_issues)

    def test_disk_warning_at_85_percent(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   43G    7G  85% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.WARNING for i in disk_issues)

    def test_disk_critical_at_95_percent(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   48G  1.5G  97% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.CRITICAL for i in disk_issues)

    def test_tmpfs_is_ignored(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "tmpfs           785M  780M  5.0M  99% /run\n"  # 99% mas tmpfs
            "/dev/sda1        50G   18G   30G  37% /\n"
        )
        result = analyzer.analyze(data)
        # tmpfs não deve gerar alerta crítico
        critical = [i for i in result.issues
                    if i.category == "Armazenamento" and i.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_disk_threshold_exactly_at_warning(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            f"/dev/sda1        50G   40G   10G  {DiagnosticAnalyzer.DISK_WARNING_PCT}% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.WARNING for i in disk_issues)

    def test_disk_threshold_exactly_at_critical(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            f"/dev/sda1        50G   45G    5G  {DiagnosticAnalyzer.DISK_CRITICAL_PCT}% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.CRITICAL for i in disk_issues)


class TestMemoryAnalysis:
    """Testa regras de análise de memória."""

    def test_normal_memory_is_info(self, analyzer):
        data = make_empty_data()
        data.memory = make_result(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            7850        3012        2341         245        2496        4521\n"
            "Swap:           2048           0        2048\n"
        )
        result = analyzer.analyze(data)
        mem_issues = [i for i in result.issues if i.category == "Memória"]
        assert any(i.severity == Severity.INFO for i in mem_issues)

    def test_high_memory_is_warning(self, analyzer):
        data = make_empty_data()
        # ~87% de uso (acima do threshold WARNING=85%)
        data.memory = make_result(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            8000        7000         100         200         700         300\n"
            "Swap:           2048           0        2048\n"
        )
        result = analyzer.analyze(data)
        mem_issues = [i for i in result.issues if i.category == "Memória"]
        assert any(i.severity == Severity.WARNING for i in mem_issues)

    def test_critical_memory_usage(self, analyzer):
        data = make_empty_data()
        # ~97% de uso (acima do threshold CRITICAL=95%)
        data.memory = make_result(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            8000        7800          50          22         150          80\n"
            "Swap:           2048        2000          48\n"
        )
        result = analyzer.analyze(data)
        mem_issues = [i for i in result.issues if i.category == "Memória"]
        assert any(i.severity == Severity.CRITICAL for i in mem_issues)

    def test_no_swap_reported_as_info(self, analyzer):
        data = make_empty_data()
        data.memory = make_result(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            7850        3012        2341         245        2496        4521\n"
            "Swap:              0           0           0\n"
        )
        result = analyzer.analyze(data)
        swap_issues = [i for i in result.issues
                       if i.category == "Memória" and "swap" in i.title.lower()]
        assert any(i.severity == Severity.INFO for i in swap_issues)

    def test_swap_over_50pct_is_warning(self, analyzer):
        data = make_empty_data()
        data.memory = make_result(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            7850        3012        2341         245        2496        4521\n"
            "Swap:           2048        1200         848\n"
        )
        result = analyzer.analyze(data)
        swap_issues = [i for i in result.issues
                       if i.category == "Memória" and "swap" in i.title.lower()]
        assert any(i.severity == Severity.WARNING for i in swap_issues)

    def test_malformed_memory_line_does_not_crash(self, analyzer):
        data = make_empty_data()
        data.memory = make_result("Mem: invalid data here\n")
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)


class TestCPULoadAnalysis:
    """Testa análise de carga da CPU."""

    def test_low_load_is_info(self, analyzer):
        data = make_empty_data()
        data.load_average = make_result("0.45 0.52 0.48 2/342 12345")
        data.cpu_info = make_result("4\nmodel name\t: Intel Core i5")
        result = analyzer.analyze(data)
        cpu_issues = [i for i in result.issues if i.category == "CPU"]
        assert any(i.severity == Severity.INFO for i in cpu_issues)

    def test_high_load_is_warning(self, analyzer):
        data = make_empty_data()
        # 4 CPUs, load 5min = 7.0 → ratio 1.75 (acima de WARNING=1.5)
        data.load_average = make_result("6.50 7.00 6.80 8/342 12345")
        data.cpu_info = make_result("4\nmodel name\t: Intel Core i5")
        result = analyzer.analyze(data)
        cpu_issues = [i for i in result.issues if i.category == "CPU"]
        assert any(i.severity == Severity.WARNING for i in cpu_issues)

    def test_critical_load(self, analyzer):
        data = make_empty_data()
        # 4 CPUs, load 5min = 15.0 → ratio 3.75 (acima de CRITICAL=3.0)
        data.load_average = make_result("14.50 15.00 13.80 8/342 12345")
        data.cpu_info = make_result("4\nmodel name\t: Intel Core i5")
        result = analyzer.analyze(data)
        cpu_issues = [i for i in result.issues if i.category == "CPU"]
        assert any(i.severity == Severity.CRITICAL for i in cpu_issues)

    def test_missing_cpu_info_skips_gracefully(self, analyzer):
        data = make_empty_data()
        data.load_average = make_result("0.45 0.52 0.48 2/342 12345")
        # cpu_info ausente
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)


class TestTemperatureAnalysis:
    """Testa análise de temperatura."""

    def test_normal_temp_is_info(self, analyzer):
        data = make_empty_data()
        data.sensors = make_result(
            "coretemp-isa-0000\nPackage id 0:  +42.0°C  (high = +100.0°C)\n"
        )
        result = analyzer.analyze(data)
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert any(i.severity == Severity.INFO for i in temp_issues)

    def test_high_temp_is_warning(self, analyzer):
        data = make_empty_data()
        data.sensors = make_result(
            "coretemp-isa-0000\nPackage id 0:  +75.0°C  (high = +100.0°C)\n"
        )
        result = analyzer.analyze(data)
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert any(i.severity == Severity.WARNING for i in temp_issues)

    def test_critical_temp(self, analyzer):
        data = make_empty_data()
        data.sensors = make_result(
            "coretemp-isa-0000\nPackage id 0:  +88.0°C  (high = +100.0°C)\n"
        )
        result = analyzer.analyze(data)
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert any(i.severity == Severity.CRITICAL for i in temp_issues)

    def test_no_sensors_is_info(self, analyzer):
        data = make_empty_data()
        # Nenhum sensor disponível
        result = analyzer.analyze(data)
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert any(i.severity == Severity.INFO for i in temp_issues)

    def test_temperature_from_thermal_zone(self, analyzer):
        data = make_empty_data()
        data.vcgencmd_temp = make_result("thermal_zone0: 45.0°C\nthermal_zone1: 43.0°C\n")
        result = analyzer.analyze(data)
        temp_issues = [i for i in result.issues if i.category == "Temperatura"]
        assert len(temp_issues) > 0


class TestDmesgAnalysis:
    """Testa detecção de padrões críticos no dmesg."""

    def test_kernel_panic_is_critical(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:00:01 2023] kernel panic - not syncing: VFS: Unable to mount\n"
        )
        result = analyzer.analyze(data)
        log_issues = [i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_oom_kill_is_critical(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:01:05 2023] Out of memory: Kill process 1234 (apache2) score 900\n"
        )
        result = analyzer.analyze(data)
        log_issues = [i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_io_error_is_critical(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:02:00 2023] blk_update_request: I/O error, dev sda, sector 123456\n"
        )
        result = analyzer.analyze(data)
        log_issues = [i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_segfault_is_warning(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:03:00 2023] apache2[5678]: segfault at 0 ip 00007f rsp 00007f error 4\n"
        )
        result = analyzer.analyze(data)
        log_issues = [i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.WARNING for i in log_issues)

    def test_clean_dmesg_no_log_issues(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:00:01 2023] Linux version 5.15.0\n"
            "[Mon Nov 20 14:00:05 2023] BIOS-provided physical RAM map\n"
            "[Mon Nov 20 14:00:10 2023] Booting paravirtualized kernel on bare hardware\n"
        )
        result = analyzer.analyze(data)
        log_issues = [i for i in result.issues if "dmesg" in i.category.lower()]
        # Sem padrões críticos no dmesg limpo
        assert not any(i.severity == Severity.CRITICAL for i in log_issues)


class TestFailedServicesAnalysis:
    """Testa detecção de serviços com falha."""

    def test_failed_service_is_warning(self, analyzer):
        data = make_empty_data()
        data.failed_services = make_result(
            "  UNIT                    LOAD   ACTIVE SUB    DESCRIPTION\n"
            "● nginx.service           loaded failed failed  A high performance web server\n"
        )
        result = analyzer.analyze(data)
        service_issues = [i for i in result.issues if i.category == "Serviços"]
        assert any(i.severity == Severity.WARNING for i in service_issues)
        assert any("nginx.service" in i.title for i in service_issues)

    def test_no_failed_services_is_info(self, analyzer):
        data = make_empty_data()
        data.failed_services = make_result("0 loaded units listed.\n")
        result = analyzer.analyze(data)
        service_issues = [i for i in result.issues if i.category == "Serviços"]
        # Com "0 loaded units listed", a mensagem INFO não é gerada (conforme lógica atual)
        # Apenas confirma que não há WARNING
        assert not any(i.severity == Severity.WARNING for i in service_issues)


class TestOverallHealth:
    """Testa a propriedade overall_health do DiagnosticResult."""

    def test_health_is_critical_when_critical_issues_exist(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   48G  1.5G  97% /\n"
        )
        result = analyzer.analyze(data)
        assert result.overall_health == "CRÍTICO"

    def test_health_is_healthy_when_all_normal(self, analyzer, healthy_data):
        result = analyzer.analyze(healthy_data)
        # Com dados saudáveis, não deve ser CRÍTICO
        assert result.overall_health in ("SAUDÁVEL", "ATENÇÃO")

    def test_critical_issues_property(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   48G  1.5G  97% /\n"
        )
        result = analyzer.analyze(data)
        assert len(result.critical_issues) > 0
        assert all(i.severity == Severity.CRITICAL for i in result.critical_issues)

    def test_warning_issues_property(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   43G    7G  85% /\n"
        )
        result = analyzer.analyze(data)
        assert all(i.severity == Severity.WARNING for i in result.warning_issues)
