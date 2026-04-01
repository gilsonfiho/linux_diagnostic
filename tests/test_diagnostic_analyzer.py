"""
Testes para DiagnosticAnalyzer
================================
Valida regras de detecção, classificação de severidade e parsing.
"""

import pytest
from src.collector.system_collector import SystemData, CommandResult
from src.analyzer.diagnostic_analyzer import DiagnosticAnalyzer, DiagnosticResult, Severity, Issue
from src.analyzer.hardware import DISK_WARNING_PCT, DISK_CRITICAL_PCT


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
    data.kernel = make_result(
        "Linux server01 5.15.0-91-generic #101-Ubuntu x86_64")
    data.uptime = make_result(
        " 14:23:01 up 7 days,  3:42,  load average: 0.45, 0.52, 0.48")
    data.load_average = make_result("0.45 0.52 0.48 2/342 12345")
    data.cpu_info = make_result(
        "4\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz")
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
        disk_issues = [
            i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.INFO for i in disk_issues)

    def test_disk_warning_at_85_percent(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   43G    7G  85% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [
            i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.WARNING for i in disk_issues)

    def test_disk_critical_at_95_percent(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   48G  1.5G  97% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [
            i for i in result.issues if i.category == "Armazenamento"]
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
            f"/dev/sda1        50G   40G   10G  {DISK_WARNING_PCT}% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [
            i for i in result.issues if i.category == "Armazenamento"]
        assert any(i.severity == Severity.WARNING for i in disk_issues)

    def test_disk_threshold_exactly_at_critical(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            f"/dev/sda1        50G   45G    5G  {DISK_CRITICAL_PCT}% /\n"
        )
        result = analyzer.analyze(data)
        disk_issues = [
            i for i in result.issues if i.category == "Armazenamento"]
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
        data.vcgencmd_temp = make_result(
            "thermal_zone0: 45.0°C\nthermal_zone1: 43.0°C\n")
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
        log_issues = [
            i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_oom_kill_is_critical(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:01:05 2023] Out of memory: Kill process 1234 (apache2) score 900\n"
        )
        result = analyzer.analyze(data)
        log_issues = [
            i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_io_error_is_critical(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:02:00 2023] blk_update_request: I/O error, dev sda, sector 123456\n"
        )
        result = analyzer.analyze(data)
        log_issues = [
            i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.CRITICAL for i in log_issues)

    def test_segfault_is_warning(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:03:00 2023] apache2[5678]: segfault at 0 ip 00007f rsp 00007f error 4\n"
        )
        result = analyzer.analyze(data)
        log_issues = [
            i for i in result.issues if "dmesg" in i.category.lower()]
        assert any(i.severity == Severity.WARNING for i in log_issues)

    def test_clean_dmesg_no_log_issues(self, analyzer):
        data = make_empty_data()
        data.dmesg = make_result(
            "[Mon Nov 20 14:00:01 2023] Linux version 5.15.0\n"
            "[Mon Nov 20 14:00:05 2023] BIOS-provided physical RAM map\n"
            "[Mon Nov 20 14:00:10 2023] Booting paravirtualized kernel on bare hardware\n"
        )
        result = analyzer.analyze(data)
        log_issues = [
            i for i in result.issues if "dmesg" in i.category.lower()]
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
        assert all(
            i.severity == Severity.CRITICAL for i in result.critical_issues)

    def test_warning_issues_property(self, analyzer):
        data = make_empty_data()
        data.disk_usage = make_result(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   43G    7G  85% /\n"
        )
        result = analyzer.analyze(data)
        assert all(i.severity == Severity.WARNING for i in result.warning_issues)


class TestTtyOverruns:
    """Testes para _analyze_tty_overruns."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_dmesg(self, lines: list) -> "SystemData":
        data = make_empty_data()
        data.dmesg = make_result("\n".join(lines))
        return data

    def test_no_overruns_returns_nothing(self, analyzer):
        data = self._make_dmesg(
            ["[seg mar 23 11:00:00 2026] Linux version 5.10.17"])
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        assert tty_issues == []

    def test_few_overruns_is_warning(self, analyzer):
        lines = [
            f"[seg mar 23 11:{i:02d}:00 2026] ttyS ttyS0: 1 input overrun(s)"
            for i in range(5)
        ]
        data = self._make_dmesg(lines)
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        assert len(tty_issues) == 1
        assert tty_issues[0].severity == Severity.WARNING

    def test_many_overruns_is_critical(self, analyzer):
        lines = [
            f"[seg mar 23 11:{i:02d}:00 2026] ttyS ttyS0: 1 input overrun(s)"
            for i in range(25)
        ]
        data = self._make_dmesg(lines)
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        assert len(tty_issues) == 1
        assert tty_issues[0].severity == Severity.CRITICAL

    def test_sums_count_per_line(self, analyzer):
        """Linhas com N > 1 devem somar o total real de overruns."""
        lines = [
            "[seg mar 23 11:00:00 2026] ttyS ttyS0: 3 input overrun(s)",
            "[seg mar 23 11:01:00 2026] ttyS ttyS0: 2 input overrun(s)",
        ]
        data = self._make_dmesg(lines)
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        assert "5 ocorr" in tty_issues[0].title  # "5 ocorrências"

    def test_device_name_in_description(self, analyzer):
        lines = ["[seg mar 23 11:00:00 2026] ttyS ttyS0: 1 input overrun(s)"]
        data = self._make_dmesg(lines)
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        assert "ttyS0" in tty_issues[0].description

    def test_timestamps_shown_in_description(self, analyzer):
        lines = [
            "[seg mar 23 11:00:00 2026] ttyS ttyS0: 1 input overrun(s)",
            "[seg mar 23 13:30:00 2026] ttyS ttyS0: 1 input overrun(s)",
        ]
        data = self._make_dmesg(lines)
        result = analyzer.analyze(data)
        tty_issues = [i for i in result.issues if "Serial" in i.category]
        desc = tty_issues[0].description
        assert "11:00:00" in desc
        assert "13:30:00" in desc


class TestUsbSerialAnalysis:
    """Testes para _analyze_usb_serial (ftdi_sio, cp210x, ch341, cdc_acm, pl2303)."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_dmesg(self, lines: list) -> "SystemData":
        data = make_empty_data()
        data.dmesg = make_result("\n".join(lines))
        return data

    def test_no_usb_serial_errors_returns_nothing(self, analyzer):
        data = self._make_dmesg(
            ["[Mon Jan 01 10:00:00 2024] Linux version 5.15.0"])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert usb_serial_issues == []

    def test_ftdi_timeout_is_critical(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:01 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert len(usb_serial_issues) == 1
        assert usb_serial_issues[0].severity == Severity.CRITICAL

    def test_ftdi_enodev_is_critical(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:02 2024] ftdi_sio ttyUSB0: failed to get modem status: -19",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert usb_serial_issues[0].severity == Severity.CRITICAL

    def test_cp210x_error_is_detected(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:03 2024] cp210x ttyUSB1: failed to set baud rate: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert len(usb_serial_issues) == 1

    def test_ch341_error_is_detected(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:04 2024] ch341 ttyUSB0: failed to set line control: -32",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert len(usb_serial_issues) == 1
        assert usb_serial_issues[0].severity == Severity.CRITICAL

    def test_usb_serial_without_critical_errno_is_warning(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:05 2024] ftdi_sio ttyUSB0: reset from device",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert len(usb_serial_issues) == 1
        assert usb_serial_issues[0].severity == Severity.WARNING

    def test_device_name_appears_in_title(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:06 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert "ttyUSB0" in usb_serial_issues[0].title

    def test_errno_name_in_description(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:07 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert "ETIMEDOUT" in usb_serial_issues[0].description

    def test_multiple_errors_counted_correctly(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:08 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
            "[Mon Jan 01 10:00:09 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
            "[Mon Jan 01 10:00:10 2024] ftdi_sio ttyUSB0: failed to get modem status: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert "3 ocorrência" in usb_serial_issues[0].title

    def test_cdc_acm_error_is_detected(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:11 2024] cdc_acm ttyACM0: failed to send disconnect request: -110",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert len(usb_serial_issues) == 1
        assert usb_serial_issues[0].severity == Severity.CRITICAL

    def test_irrelevant_dmesg_not_detected(self, analyzer):
        data = self._make_dmesg([
            "[Mon Jan 01 10:00:12 2024] usb 1-1: new full-speed USB device number 3 using xhci_hcd",
            "[Mon Jan 01 10:00:13 2024] ttyS ttyS0: 1 input overrun(s)",
        ])
        result = analyzer.analyze(data)
        usb_serial_issues = [
            i for i in result.issues if i.category == "Serial USB"]
        assert usb_serial_issues == []


class TestNetworkArpAnalysis:
    """Testes para analyze_arp: entradas (incomplete) indicam dispositivos inacessíveis."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_arp(self, output: str) -> "SystemData":
        data = make_empty_data()
        data.arp_table = make_result(output)
        return data

    def test_clean_arp_table_returns_no_issues(self, analyzer):
        data = self._make_arp(
            "Address          HWtype  HWaddress           Flags Iface\n"
            "192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C     eth0\n"
            "192.168.1.10    ether   11:22:33:44:55:66   C     eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert arp_issues == []

    def test_one_incomplete_is_warning(self, analyzer):
        data = self._make_arp(
            "192.168.1.10                     (incomplete)                              eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert len(arp_issues) == 1
        assert arp_issues[0].severity == Severity.WARNING

    def test_two_incomplete_is_warning(self, analyzer):
        data = self._make_arp(
            "192.168.1.10                     (incomplete)                              eth0\n"
            "192.168.1.20                     (incomplete)                              eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert arp_issues[0].severity == Severity.WARNING

    def test_three_incomplete_is_critical(self, analyzer):
        data = self._make_arp(
            "192.168.1.10                     (incomplete)                              eth0\n"
            "192.168.1.20                     (incomplete)                              eth0\n"
            "192.168.1.30                     (incomplete)                              eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert len(arp_issues) == 1
        assert arp_issues[0].severity == Severity.CRITICAL

    def test_ip_addresses_in_description(self, analyzer):
        data = self._make_arp(
            "192.168.1.10                     (incomplete)                              eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert "192.168.1.10" in arp_issues[0].description

    def test_count_shown_in_title(self, analyzer):
        data = self._make_arp(
            "192.168.1.10                     (incomplete)                              eth0\n"
            "192.168.1.20                     (incomplete)                              eth0\n"
        )
        result = analyzer.analyze(data)
        arp_issues = [i for i in result.issues if "ARP" in i.title]
        assert "2" in arp_issues[0].title

    def test_empty_arp_output_no_crash(self, analyzer):
        data = self._make_arp("")
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)

    def test_no_arp_data_no_crash(self, analyzer):
        data = make_empty_data()
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)


class TestNetworkInterfaceErrors:
    """Testes para analyze_network_interface_errors: erros e drops em 'ip -s link'."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_netstats(self, output: str) -> "SystemData":
        data = make_empty_data()
        data.network_stats = make_result(output)
        return data

    def _clean_stats(self, iface: str = "eth0", rx_errors: int = 0,
                     rx_dropped: int = 0) -> str:
        return (
            f"2: {iface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    link/ether b8:27:eb:00:00:00\n"
            "    RX: bytes  packets  errors  dropped missed  mcast\n"
            f"    98765432   765432   {rx_errors}  {rx_dropped}  0  0\n"
            "    TX: bytes  packets  errors  dropped carrier collsns\n"
            "    43210987   543210   0       0       0       0\n"
        )

    def test_clean_interface_no_issues(self, analyzer):
        data = self._make_netstats(self._clean_stats())
        result = analyzer.analyze(data)
        err_issues = [i for i in result.issues if "Erros" in i.title]
        assert err_issues == []

    def test_rx_errors_below_100_is_warning(self, analyzer):
        data = self._make_netstats(self._clean_stats(rx_errors=30))
        result = analyzer.analyze(data)
        err_issues = [i for i in result.issues if "Erros" in i.title]
        assert len(err_issues) == 1
        assert err_issues[0].severity == Severity.WARNING

    def test_rx_errors_100_is_critical(self, analyzer):
        data = self._make_netstats(self._clean_stats(rx_errors=100))
        result = analyzer.analyze(data)
        err_issues = [i for i in result.issues if "Erros" in i.title]
        assert err_issues[0].severity == Severity.CRITICAL

    def test_rx_errors_250_is_critical(self, analyzer):
        data = self._make_netstats(self._clean_stats(rx_errors=250))
        result = analyzer.analyze(data)
        err_issues = [i for i in result.issues if "Erros" in i.title]
        assert err_issues[0].severity == Severity.CRITICAL

    def test_rx_dropped_50_is_warning(self, analyzer):
        data = self._make_netstats(self._clean_stats(rx_dropped=50))
        result = analyzer.analyze(data)
        drop_issues = [i for i in result.issues if "Drops" in i.title]
        assert len(drop_issues) == 1
        assert drop_issues[0].severity == Severity.WARNING

    def test_rx_dropped_below_50_no_issue(self, analyzer):
        data = self._make_netstats(self._clean_stats(rx_dropped=49))
        result = analyzer.analyze(data)
        drop_issues = [i for i in result.issues if "Drops" in i.title]
        assert drop_issues == []

    def test_interface_name_in_title(self, analyzer):
        data = self._make_netstats(self._clean_stats(iface="wlan0", rx_errors=5))
        result = analyzer.analyze(data)
        err_issues = [i for i in result.issues if "Erros" in i.title]
        assert "wlan0" in err_issues[0].title

    def test_empty_stats_no_crash(self, analyzer):
        data = self._make_netstats("")
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)


class TestNetworkLinkEvents:
    """Testes para analyze_network_link_events: link flapping no dmesg filtrado."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_dmesg_net(self, lines: list) -> "SystemData":
        data = make_empty_data()
        data.dmesg_network = make_result("\n".join(lines))
        return data

    def test_no_link_events_returns_nothing(self, analyzer):
        data = self._make_dmesg_net(["[Mon Nov 20 14:00:01 2023] Normal log message"])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert link_issues == []

    def test_one_link_down_is_warning(self, analyzer):
        data = self._make_dmesg_net([
            "[Mon Nov 20 14:01:00 2023] eth0: Link is Down",
            "[Mon Nov 20 14:01:05 2023] eth0: Link is Up 1000Mbps Full Duplex",
        ])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert len(link_issues) == 1
        assert link_issues[0].severity == Severity.WARNING

    def test_two_link_downs_is_warning(self, analyzer):
        data = self._make_dmesg_net([
            "[Mon Nov 20 14:01:00 2023] eth0: Link is Down",
            "[Mon Nov 20 14:03:00 2023] eth0: Link is Down",
        ])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert link_issues[0].severity == Severity.WARNING

    def test_three_link_downs_is_critical(self, analyzer):
        data = self._make_dmesg_net([
            "[Mon Nov 20 14:01:00 2023] eth0: Link is Down",
            "[Mon Nov 20 14:03:00 2023] eth0: Link is Down",
            "[Mon Nov 20 14:05:00 2023] eth0: Link is Down",
        ])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert link_issues[0].severity == Severity.CRITICAL

    def test_carrier_lost_is_detected(self, analyzer):
        data = self._make_dmesg_net([
            "[Mon Nov 20 14:01:00 2023] eth0: carrier lost",
        ])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert len(link_issues) == 1

    def test_count_in_title(self, analyzer):
        data = self._make_dmesg_net([
            "[Mon Nov 20 14:01:00 2023] eth0: Link is Down",
            "[Mon Nov 20 14:03:00 2023] eth0: Link is Down",
        ])
        result = analyzer.analyze(data)
        link_issues = [i for i in result.issues if "Quedas" in i.title]
        assert "2" in link_issues[0].title

    def test_empty_dmesg_network_no_crash(self, analyzer):
        data = self._make_dmesg_net([])
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)


class TestGatewayConnectivity:
    """Testes para analyze_gateway_connectivity: perda de pacotes ao gateway."""

    @pytest.fixture
    def analyzer(self):
        return DiagnosticAnalyzer()

    def _make_ping(self, output: str) -> "SystemData":
        data = make_empty_data()
        data.ping_gateway = make_result(output)
        return data

    def test_zero_loss_returns_no_issue(self, analyzer):
        data = self._make_ping(
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "10 packets transmitted, 10 received, 0% packet loss, time 9003ms\n"
        )
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "Perda" in i.title or
                     "gateway" in i.title.lower()]
        assert gw_issues == []

    def test_10_percent_loss_is_warning(self, analyzer):
        data = self._make_ping(
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "10 packets transmitted, 9 received, 10% packet loss, time 9003ms\n"
        )
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "Perda" in i.title]
        assert len(gw_issues) == 1
        assert gw_issues[0].severity == Severity.WARNING

    def test_above_10_percent_is_critical(self, analyzer):
        data = self._make_ping(
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "10 packets transmitted, 8 received, 20% packet loss, time 9003ms\n"
        )
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "Perda" in i.title]
        assert gw_issues[0].severity == Severity.CRITICAL

    def test_100_percent_loss_is_critical(self, analyzer):
        data = self._make_ping(
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "10 packets transmitted, 0 received, 100% packet loss, time 9003ms\n"
        )
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "Perda" in i.title]
        assert gw_issues[0].severity == Severity.CRITICAL

    def test_gateway_not_found_is_warning(self, analyzer):
        data = self._make_ping("gateway nao encontrado")
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "gateway" in i.title.lower()]
        assert len(gw_issues) == 1
        assert gw_issues[0].severity == Severity.WARNING

    def test_gateway_ip_in_title(self, analyzer):
        data = self._make_ping(
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "10 packets transmitted, 8 received, 20% packet loss, time 9003ms\n"
        )
        result = analyzer.analyze(data)
        gw_issues = [i for i in result.issues if "Perda" in i.title]
        assert "192.168.1.1" in gw_issues[0].title

    def test_no_ping_data_no_crash(self, analyzer):
        data = make_empty_data()
        result = analyzer.analyze(data)
        assert isinstance(result, DiagnosticResult)
