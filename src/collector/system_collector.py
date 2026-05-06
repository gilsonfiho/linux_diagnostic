"""
System Collector
=================
Módulo responsável pela coleta de dados do sistema Linux via SSH.
Executa uma série de comandos diagnósticos e armazena os resultados.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional

from src.collector.ssh_client import SSHClient

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Resultado de um comando executado via SSH."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool

    @property
    def output(self) -> str:
        """Retorna stdout ou stderr se stdout vazio."""
        return self.stdout if self.stdout else self.stderr


@dataclass
class SystemData:
    """
    Contêiner para todos os dados coletados do sistema.
    Cada campo corresponde a um grupo de informações do sistema.
    """
    # Identificação do sistema
    hostname: CommandResult = None
    os_info: CommandResult = None
    kernel: CommandResult = None

    # Performance
    uptime: CommandResult = None
    top: CommandResult = None
    cpu_info: CommandResult = None
    memory: CommandResult = None
    load_average: CommandResult = None

    # Armazenamento
    disk_usage: CommandResult = None
    block_devices: CommandResult = None
    inode_usage: CommandResult = None

    # Temperatura e hardware
    sensors: CommandResult = None
    vcgencmd_temp: CommandResult = None  # Raspberry Pi

    # Dispositivos USB
    lsusb: CommandResult = None
    lsusb_verbose: CommandResult = None
    usb_errors: CommandResult = None

    # Logs e erros do sistema
    dmesg: CommandResult = None
    journalctl_errors: CommandResult = None
    syslog_errors: CommandResult = None

    # Rede
    network_interfaces: CommandResult = None
    open_ports: CommandResult = None
    arp_table: CommandResult = None
    network_stats: CommandResult = None
    ping_gateway: CommandResult = None
    dmesg_network: CommandResult = None

    # Processos
    top_processes: CommandResult = None

    # Serviços
    failed_services: CommandResult = None

    # Metadados da coleta
    collection_errors: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Optional[CommandResult]]:
        """Converte para dicionário para facilitar iteração."""
        return {
            k: v for k, v in self.__dict__.items()
            if k != "collection_errors"
        }


class SystemCollector:
    """
    Coleta informações diagnósticas de um sistema Linux remoto.

    Executa comandos via SSH e armazena os resultados em um objeto SystemData.
    Comandos que falham são registrados em log mas não interrompem a coleta.
    """

    # Comandos e seus timeouts específicos (segundos)
    # lsusb -v pode demorar mais em sistemas com muitos dispositivos
    COMMAND_TIMEOUTS = {
        "lsusb_verbose": 60,
        "dmesg": 45,
        "journalctl_errors": 45,
        "sensors": 15,
    }

    def __init__(
        self,
        ssh_client: SSHClient,
        is_raspberry_pi: bool = False,
        timeout: int = 30,
    ):
        """
        Inicializa o coletor de dados.

        Args:
            ssh_client: Cliente SSH já conectado.
            is_raspberry_pi: Ativa coleta específica para Raspberry Pi.
            timeout: Timeout padrão para comandos em segundos.
        """
        self.ssh = ssh_client
        self.is_raspberry_pi = is_raspberry_pi
        self.default_timeout = timeout

    def _run(self, command: str, key: str = "") -> CommandResult:
        """
        Executa um comando e retorna CommandResult.
        Em caso de erro, registra em log e retorna resultado vazio.

        Args:
            command: Comando a executar.
            key: Chave para buscar timeout específico.

        Returns:
            CommandResult com os dados da execução.
        """
        timeout = self.COMMAND_TIMEOUTS.get(key, self.default_timeout)

        try:
            out, err, code = self.ssh.execute_command(
                command,
                timeout=timeout,
                ignore_errors=True,
            )
            return CommandResult(
                command=command,
                stdout=out,
                stderr=err,
                exit_code=code,
                success=(code == 0),
            )
        except Exception as e:
            logger.warning(f"Falha ao executar '{command}': {e}")
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                success=False,
            )

    def collect_all(self) -> SystemData:
        """
        Executa a coleta completa de todos os dados do sistema.

        Returns:
            SystemData com todos os dados coletados.
        """
        data = SystemData()

        logger.info("Coletando informações do sistema...")

        # --- Identificação ---
        logger.debug("  Coletando identificação do sistema")
        data.hostname = self._run("hostname -f", "hostname")
        data.os_info = self._run("cat /etc/os-release", "os_info")
        data.kernel = self._run("uname -a", "kernel")

        # --- Performance ---
        logger.debug("  Coletando métricas de performance")
        data.uptime = self._run("uptime", "uptime")
        data.load_average = self._run("cat /proc/loadavg", "load_average")
        data.cpu_info = self._run(
            "nproc && grep 'model name' /proc/cpuinfo | head -1", "cpu_info"
        )
        # top -bn1: executa em modo batch, 1 iteração — alternativa ao htop
        data.top = self._run("top -bn1 | head -20", "top")
        data.memory = self._run("free -m", "memory")

        # --- Armazenamento ---
        logger.debug("  Coletando informações de disco")
        data.disk_usage = self._run("df -h", "disk_usage")
        data.block_devices = self._run(
            "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID", "block_devices")
        data.inode_usage = self._run("df -i", "inode_usage")

        # --- Temperatura ---
        logger.debug("  Coletando temperatura")
        # sensors: lm-sensors; falha silenciosa se não instalado
        data.sensors = self._run(
            "sensors 2>/dev/null || echo 'sensors não disponível'", "sensors")

        # Coleta de temperatura via múltiplas fontes (prioridade: sensors > vcgencmd > sysfs)
        # Formato normalizado de saída: "zone_name: XX.X°C"
        if self.is_raspberry_pi:
            # Raspberry Pi: vcgencmd (nativo) com fallback para /sys/class/thermal
            # vcgencmd measure_temp → "temp=45.0'C"
            # /sys/class/thermal/thermal_zone0/temp → 45000 (milicélsius)
            temp_cmd = (
                "( vcgencmd measure_temp 2>/dev/null || "
                "( [ -f /sys/class/thermal/thermal_zone0/temp ] && "
                "awk '{printf \"thermal_zone0: %.1f°C\\n\", $1/1000}' /sys/class/thermal/thermal_zone0/temp ) || "
                "echo 'temperature not available' )"
            )
            data.vcgencmd_temp = self._run(temp_cmd, "vcgencmd_temp")
        else:
            # x86_64 e arquiteturas com múltiplas thermal_zones
            # Lê todos os /sys/class/thermal/thermal_zone*/temp e normaliza o formato
            temp_cmd = (
                "( for f in /sys/class/thermal/thermal_zone*/temp 2>/dev/null; do "
                "zone=$(basename $(dirname $f)); "
                "awk -v z=\"$zone\" '{printf \"%s: %.1f°C\\n\", z, $1/1000}' $f; "
                "done ) || echo 'temperature not available'"
            )
            data.vcgencmd_temp = self._run(temp_cmd, "vcgencmd_temp")

        # --- USB ---
        logger.debug("  Coletando informações USB")
        data.lsusb = self._run("lsusb", "lsusb")
        # lsusb -v pode requerer sudo; tenta com e sem
        data.lsusb_verbose = self._run(
            "lsusb -v 2>/dev/null | head -200", "lsusb_verbose"
        )
        # Erros USB no kernel ring buffer
        data.usb_errors = self._run(
            "dmesg -T 2>/dev/null | grep -iE '(usb|hub|port).*error|disconnect|over.current|reset' | tail -50",
            "usb_errors",
        )

        # --- Logs e Erros ---
        logger.debug("  Coletando logs e erros")
        # dmesg -T: timestamps legíveis por evento (data/hora exata de cada ocorrência)
        # Sem filtro de nível: link is down, usb disconnect, ttyS overrun são nível notice/info
        # e seriam perdidos com --level err,warn. O ring buffer do kernel é fixo (~512KB).
        data.dmesg = self._run(
            "dmesg -T 2>/dev/null",
            "dmesg",
        )
        # journalctl -p 3: prioridade 3 = ERR e acima; -xb: boot atual com contexto
        data.journalctl_errors = self._run(
            "journalctl -p 3 -xb --no-pager 2>/dev/null | tail -150 || "
            "grep -i 'error\\|critical\\|fail' /var/log/syslog 2>/dev/null | tail -100",
            "journalctl_errors",
        )
        # Fallback para sistemas sem journalctl
        data.syslog_errors = self._run(
            "tail -n 100 /var/log/syslog 2>/dev/null || "
            "tail -n 100 /var/log/messages 2>/dev/null || echo 'syslog não disponível'",
            "syslog_errors",
        )

        # --- Rede ---
        logger.debug("  Coletando informações de rede")
        data.network_interfaces = self._run(
            "ip addr show 2>/dev/null || ifconfig 2>/dev/null", "network_interfaces"
        )
        data.open_ports = self._run(
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -30",
            "open_ports",
        )
        data.arp_table = self._run(
            "arp -n 2>/dev/null || ip neigh show 2>/dev/null",
            "arp_table",
        )
        data.network_stats = self._run(
            "ip -s link 2>/dev/null",
            "network_stats",
        )
        # Ping ao gateway padrão (10 pacotes, timeout 1s por pacote)
        data.ping_gateway = self._run(
            "gw=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}'); "
            "[ -n \"$gw\" ] && ping -c 10 -W 1 \"$gw\" 2>/dev/null "
            "|| echo 'gateway nao encontrado'",
            "ping_gateway",
        )
        # Eventos de link do kernel (link up/down, carrier lost)
        data.dmesg_network = self._run(
            "dmesg -T 2>/dev/null | grep -iE "
            "'(link is (up|down)|NIC link is|carrier (lost|found)|link failure)' | tail -50",
            "dmesg_network",
        )

        # --- Processos ---
        logger.debug("  Coletando processos")
        data.top_processes = self._run(
            "ps aux --sort=-%cpu | head -20", "top_processes"
        )

        # --- Serviços ---
        logger.debug("  Coletando status de serviços")
        data.failed_services = self._run(
            "systemctl --failed --no-pager 2>/dev/null || "
            "service --status-all 2>&1 | grep -E '\\[ - \\]' | head -20",
            "failed_services",
        )

        # Conta itens coletados com sucesso
        results = data.to_dict()
        success_count = sum(
            1 for v in results.values()
            if isinstance(v, CommandResult) and v.success
        )
        total = sum(1 for v in results.values()
                    if isinstance(v, CommandResult))
        logger.info(
            f"Coleta finalizada: {success_count}/{total} comandos bem-sucedidos")

        return data
