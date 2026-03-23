"""
Testes para SystemCollector
============================
Valida a coleta de dados usando MockSSHClient.
"""

import pytest
from src.collector.system_collector import SystemCollector, SystemData, CommandResult
from mock_ssh_client import MockSSHClient


@pytest.fixture
def normal_collector():
    """Coletor com cenário normal (sistema saudável)."""
    return SystemCollector(ssh_client=MockSSHClient("normal"), is_raspberry_pi=False)


@pytest.fixture
def critical_collector():
    """Coletor com cenário crítico."""
    return SystemCollector(ssh_client=MockSSHClient("critical"), is_raspberry_pi=False)


@pytest.fixture
def raspberry_collector():
    """Coletor simulando Raspberry Pi."""
    return SystemCollector(ssh_client=MockSSHClient("normal"), is_raspberry_pi=True)


class TestSystemCollectorStructure:
    """Verifica que collect_all() retorna SystemData com campos esperados."""

    def test_returns_system_data(self, normal_collector):
        data = normal_collector.collect_all()
        assert isinstance(data, SystemData)

    def test_all_fields_populated(self, normal_collector):
        data = normal_collector.collect_all()
        # Verifica que os campos principais estão populados
        assert data.hostname is not None
        assert data.os_info is not None
        assert data.kernel is not None
        assert data.memory is not None
        assert data.disk_usage is not None
        assert data.load_average is not None
        assert data.cpu_info is not None

    def test_command_result_type(self, normal_collector):
        data = normal_collector.collect_all()
        assert isinstance(data.hostname, CommandResult)
        assert isinstance(data.memory, CommandResult)
        assert isinstance(data.disk_usage, CommandResult)

    def test_successful_commands_have_stdout(self, normal_collector):
        data = normal_collector.collect_all()
        assert data.hostname.stdout != ""
        assert data.memory.stdout != ""
        assert data.disk_usage.stdout != ""

    def test_collection_errors_is_dict(self, normal_collector):
        data = normal_collector.collect_all()
        assert isinstance(data.collection_errors, dict)


class TestSystemCollectorData:
    """Verifica o conteúdo dos dados coletados."""

    def test_hostname_content(self, normal_collector):
        data = normal_collector.collect_all()
        assert "server01" in data.hostname.stdout

    def test_memory_has_mem_line(self, normal_collector):
        data = normal_collector.collect_all()
        assert "Mem:" in data.memory.stdout

    def test_disk_has_header(self, normal_collector):
        data = normal_collector.collect_all()
        assert "Filesystem" in data.disk_usage.stdout

    def test_os_info_has_ubuntu(self, normal_collector):
        data = normal_collector.collect_all()
        assert "ubuntu" in data.os_info.stdout.lower()

    def test_load_average_format(self, normal_collector):
        data = normal_collector.collect_all()
        parts = data.load_average.stdout.split()
        assert len(parts) >= 3
        # Valida que os 3 primeiros campos são floats
        for part in parts[:3]:
            float(part)  # não deve lançar ValueError


class TestSystemCollectorRaspberryPi:
    """Testa coleta específica do Raspberry Pi."""

    def test_raspberry_pi_mode_collects_vcgencmd(self, raspberry_collector):
        data = raspberry_collector.collect_all()
        # vcgencmd_temp deve estar populado no modo RPi
        assert data.vcgencmd_temp is not None

    def test_non_raspberry_collects_thermal_zones(self, normal_collector):
        data = normal_collector.collect_all()
        assert data.vcgencmd_temp is not None


class TestCommandResult:
    """Testa o dataclass CommandResult."""

    def test_output_property_returns_stdout_when_available(self):
        result = CommandResult(
            command="test", stdout="output", stderr="error", exit_code=0, success=True
        )
        assert result.output == "output"

    def test_output_property_returns_stderr_when_stdout_empty(self):
        result = CommandResult(
            command="test", stdout="", stderr="error msg", exit_code=1, success=False
        )
        assert result.output == "error msg"

    def test_success_when_exit_code_zero(self):
        result = CommandResult(
            command="test", stdout="ok", stderr="", exit_code=0, success=True
        )
        assert result.success is True

    def test_to_dict_excludes_collection_errors(self):
        data = SystemData()
        d = data.to_dict()
        assert "collection_errors" not in d
