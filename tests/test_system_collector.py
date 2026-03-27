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


class TestNetworkCollection:
    """Verifica coleta dos novos campos de rede: arp_table, network_stats, ping_gateway, dmesg_network."""

    def test_arp_table_is_collected(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert data.arp_table is not None
        assert isinstance(data.arp_table, CommandResult)

    def test_network_stats_is_collected(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert data.network_stats is not None
        assert isinstance(data.network_stats, CommandResult)

    def test_ping_gateway_is_collected(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert data.ping_gateway is not None
        assert isinstance(data.ping_gateway, CommandResult)

    def test_dmesg_network_is_collected(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert data.dmesg_network is not None
        assert isinstance(data.dmesg_network, CommandResult)

    def test_arp_table_has_expected_content_normal(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert "192.168.1.1" in data.arp_table.stdout

    def test_network_stats_has_eth0_normal(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert "eth0" in data.network_stats.stdout

    def test_ping_gateway_has_packet_stats_normal(self):
        collector = SystemCollector(ssh_client=MockSSHClient("normal"))
        data = collector.collect_all()
        assert "packet loss" in data.ping_gateway.stdout

    def test_critical_arp_has_incomplete(self):
        collector = SystemCollector(ssh_client=MockSSHClient("critical"))
        data = collector.collect_all()
        assert "(incomplete)" in data.arp_table.stdout

    def test_critical_network_stats_has_errors(self):
        collector = SystemCollector(ssh_client=MockSSHClient("critical"))
        data = collector.collect_all()
        # 250 erros no cenário crítico
        assert "250" in data.network_stats.stdout

    def test_critical_ping_has_packet_loss(self):
        collector = SystemCollector(ssh_client=MockSSHClient("critical"))
        data = collector.collect_all()
        assert "20%" in data.ping_gateway.stdout

    def test_warning_arp_has_incomplete(self):
        collector = SystemCollector(ssh_client=MockSSHClient("warnings"))
        data = collector.collect_all()
        assert "(incomplete)" in data.arp_table.stdout

    def test_warning_dmesg_network_has_link_events(self):
        collector = SystemCollector(ssh_client=MockSSHClient("warnings"))
        data = collector.collect_all()
        assert "Link is Down" in data.dmesg_network.stdout
