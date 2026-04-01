"""
Mock SSH Client
================
Simula um SSHClient para testes sem necessidade de conexão real.

Retorna outputs realistas de comandos Linux para validar a lógica
de coleta e análise sem precisar de um servidor SSH disponível.
"""

from typing import Tuple, Optional


MOCK_OUTPUTS = {
    "hostname": ("server01.local", "", 0),
    "os-release": (
        'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n',
        "", 0,
    ),
    "uname": (
        "Linux server01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
        "", 0,
    ),
    "uptime": (
        " 14:23:01 up 7 days,  3:42,  2 users,  load average: 0.45, 0.52, 0.48",
        "", 0,
    ),
    "loadavg": ("0.45 0.52 0.48 2/342 12345", "", 0),
    "nproc": ("4\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "", 0),
    "top -bn1": (
        "top - 14:23:01 up 7 days,  3:42,  2 users,  load average: 0.45, 0.52, 0.48\n"
        "Tasks: 185 total,   1 running, 184 sleeping,   0 stopped,   0 zombie\n"
        "%Cpu(s):  5.2 us,  1.3 sy,  0.0 ni, 92.8 id,  0.5 wa,  0.0 hi,  0.2 si,  0.0 st\n"
        "MiB Mem :   7850.3 total,   2341.5 free,   3012.8 used,   2496.0 buff/cache\n"
        "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   4521.2 avail Mem\n",
        "", 0,
    ),
    "free -m": (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:            7850        3012        2341         245        2496        4521\n"
        "Swap:           2048           0        2048\n",
        "", 0,
    ),
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "udev            3.8G     0  3.8G   0% /dev\n"
        "tmpfs           785M  1.6M  784M   1% /run\n"
        "/dev/sda1        50G   18G   30G  37% /\n"
        "/dev/sda2       100G   75G   20G  79% /data\n"
        "tmpfs           3.9G     0  3.9G   0% /dev/shm\n",
        "", 0,
    ),
    "lsblk": (
        "NAME   SIZE TYPE FSTYPE MOUNTPOINT UUID\n"
        "sda    160G disk\n"
        "├─sda1  50G part ext4   /          a1b2c3d4-e5f6-7890-abcd-ef1234567890\n"
        "└─sda2 100G part ext4   /data       b2c3d4e5-f6a7-8901-bcde-f12345678901\n",
        "", 0,
    ),
    "df -i": (
        "Filesystem     Inodes  IUsed   IFree IUse% Mounted on\n"
        "/dev/sda1     3276800 182450 3094350    6% /\n"
        "/dev/sda2     6553600 412300 6141300    7% /data\n",
        "", 0,
    ),
    "sensors": (
        "coretemp-isa-0000\nAdapter: ISA adapter\n"
        "Package id 0:  +42.0°C  (high = +100.0°C, crit = +100.0°C)\n"
        "Core 0:        +40.0°C  (high = +100.0°C, crit = +100.0°C)\n"
        "Core 1:        +41.0°C  (high = +100.0°C, crit = +100.0°C)\n"
        "Core 2:        +39.0°C  (high = +100.0°C, crit = +100.0°C)\n"
        "Core 3:        +42.0°C  (high = +100.0°C, crit = +100.0°C)\n",
        "", 0,
    ),
    "thermal_zone": (
        "thermal_zone0: 42.0°C\nthermal_zone1: 38.5°C\n",
        "", 0,
    ),
    "lsusb": (
        "Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub\n"
        "Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver\n"
        "Bus 001 Device 003: ID 0bda:8153 Realtek Semiconductor Corp. RTL8153 Gigabit Ethernet Adapter\n"
        "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n",
        "", 0,
    ),
    "lsusb -v": ("(verbose USB info suprimido no mock)", "", 0),
    "usb_errors": ("", "", 0),  # sem erros USB por padrão
    "arp_table": (
        "Address          HWtype  HWaddress           Flags Iface\n"
        "192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C     eth0\n"
        "192.168.1.10    ether   11:22:33:44:55:66   C     eth0\n",
        "", 0,
    ),
    "network_stats": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    link/loopback 00:00:00:00:00:00\n"
        "    RX: bytes  packets  errors  dropped missed  mcast\n"
        "    1234567    12345    0       0       0       0\n"
        "    TX: bytes  packets  errors  dropped carrier collsns\n"
        "    1234567    12345    0       0       0       0\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    link/ether b8:27:eb:xx:xx:xx\n"
        "    RX: bytes  packets  errors  dropped missed  mcast\n"
        "    98765432   765432   0       0       0       1234\n"
        "    TX: bytes  packets  errors  dropped carrier collsns\n"
        "    43210987   543210   0       0       0       0\n",
        "", 0,
    ),
    "ping_gateway": (
        "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
        "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms\n"
        "10 packets transmitted, 10 received, 0% packet loss, time 9003ms\n",
        "", 0,
    ),
    "dmesg_network": ("", "", 0),
    "dmesg": (
        "[Mon Nov 20 14:00:01 2023] Linux version 5.15.0-91-generic\n"
        "[Mon Nov 20 14:00:05 2023] BIOS-provided physical RAM map:\n"
        "[Mon Nov 20 14:00:10 2023] Booting paravirtualized kernel on bare hardware\n"
        "[Mon Nov 20 14:15:03 2023] usb 1-1.2: new high-speed USB device number 4 using xhci_hcd\n"
        "[Mon Nov 20 14:15:03 2023] usb 1-1.2: New USB device found\n",
        "", 0,
    ),
    "journalctl": (
        "Nov 20 14:00:01 server01 systemd[1]: Started System Logging Service.\n"
        "Nov 20 14:00:02 server01 systemd[1]: Started Network Time Service.\n"
        "Nov 20 14:01:00 server01 kernel: EXT4-fs (sda1): mounted filesystem\n",
        "", 0,
    ),
    "syslog": ("Nov 20 14:00:01 server01 systemd[1]: Startup finished in 3.456s.\n", "", 0),
    "ip addr": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n",
        "", 0,
    ),
    "ss -tlnp": (
        "State   Recv-Q  Send-Q   Local Address:Port\n"
        "LISTEN  0       128            0.0.0.0:22\n"
        "LISTEN  0       128            0.0.0.0:80\n",
        "", 0,
    ),
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1 169048  8312 ?        Ss   Nov20   0:05 /sbin/init\n"
        "root       512  0.1  0.5 256828 40230 ?        Ss   Nov20   1:23 /usr/sbin/sshd\n"
        "www-data  1024  2.3  1.2 456320 95840 ?        S    Nov20  25:10 /usr/sbin/apache2\n",
        "", 0,
    ),
    "systemctl --failed": (
        "  UNIT LOAD ACTIVE SUB DESCRIPTION\n"
        "0 loaded units listed.\n",
        "", 0,
    ),
}


def _match_command(command: str) -> Tuple[str, str, int]:
    """Retorna output mockado baseado em substrings do comando."""
    cmd = command.lower()

    if "hostname" in cmd:
        return MOCK_OUTPUTS["hostname"]
    elif "os-release" in cmd:
        return MOCK_OUTPUTS["os-release"]
    elif "uname" in cmd:
        return MOCK_OUTPUTS["uname"]
    elif "loadavg" in cmd:
        return MOCK_OUTPUTS["loadavg"]
    elif "nproc" in cmd or "cpuinfo" in cmd:
        return MOCK_OUTPUTS["nproc"]
    elif "top -bn1" in cmd:
        return MOCK_OUTPUTS["top -bn1"]
    elif "free -m" in cmd:
        return MOCK_OUTPUTS["free -m"]
    elif "df -h" in cmd:
        return MOCK_OUTPUTS["df -h"]
    elif "df -i" in cmd:
        return MOCK_OUTPUTS["df -i"]
    elif "lsblk" in cmd:
        return MOCK_OUTPUTS["lsblk"]
    elif "sensors" in cmd and "vcgencmd" not in cmd:
        return MOCK_OUTPUTS["sensors"]
    elif "thermal_zone" in cmd or "vcgencmd" in cmd:
        return MOCK_OUTPUTS["thermal_zone"]
    elif "lsusb -v" in cmd:
        return MOCK_OUTPUTS["lsusb -v"]
    elif "lsusb" in cmd:
        return MOCK_OUTPUTS["lsusb"]
    elif "usb" in cmd and "dmesg" in cmd:
        return MOCK_OUTPUTS["usb_errors"]
    elif "dmesg" in cmd and ("link is" in cmd or "carrier" in cmd or "nic link" in cmd):
        return MOCK_OUTPUTS["dmesg_network"]
    elif "dmesg" in cmd:
        return MOCK_OUTPUTS["dmesg"]
    elif "journalctl" in cmd:
        return MOCK_OUTPUTS["journalctl"]
    elif "syslog" in cmd or "messages" in cmd:
        return MOCK_OUTPUTS["syslog"]
    elif "ip addr" in cmd or "ifconfig" in cmd:
        return MOCK_OUTPUTS["ip addr"]
    elif "ip -s" in cmd:
        return MOCK_OUTPUTS["network_stats"]
    elif "arp -n" in cmd or "ip neigh" in cmd:
        return MOCK_OUTPUTS["arp_table"]
    elif "ping" in cmd:
        return MOCK_OUTPUTS["ping_gateway"]
    elif "ss -tlnp" in cmd or "netstat" in cmd:
        return MOCK_OUTPUTS["ss -tlnp"]
    elif "ps aux" in cmd:
        return MOCK_OUTPUTS["ps aux"]
    elif "systemctl" in cmd and "failed" in cmd:
        return MOCK_OUTPUTS["systemctl --failed"]
    elif "uptime" in cmd:
        return MOCK_OUTPUTS["uptime"]
    # Fallback
    return ("", "comando não reconhecido pelo mock", 0)


class MockSSHClient:
    """
    Mock do SSHClient para testes sem conexão real.

    Implementa a mesma interface que SSHClient, retornando
    outputs pré-definidos que simulam respostas Linux realistas.

    Uso:
        mock = MockSSHClient(scenario="normal")
        collector = SystemCollector(ssh_client=mock)
        data = collector.collect_all()
    """

    def __init__(self, scenario: str = "normal"):
        """
        Args:
            scenario: Cenário de teste.
                "normal"   — sistema saudável
                "critical" — disco cheio, CPU alta, temperatura crítica
                "warnings" — serviços falhos, swap em uso
        """
        self.scenario = scenario
        self._connected = True

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        ignore_errors: bool = False,
    ) -> Tuple[str, str, int]:
        """Retorna outputs mockados baseados no comando e cenário."""
        if self.scenario == "critical":
            return self._critical_outputs(command)
        elif self.scenario == "warnings":
            return self._warning_outputs(command)
        return _match_command(command)

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def __enter__(self) -> "MockSSHClient":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()

    # --- Cenários especiais ---

    def _critical_outputs(self, command: str) -> Tuple[str, str, int]:
        """Simula sistema em estado crítico."""
        cmd = command.lower()

        if "df -h" in cmd:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        50G   48G  1.5G  97% /\n"  # disco crítico
                "/dev/sda2       100G   93G  5.0G  95% /data\n",  # disco crítico
                "", 0,
            )
        elif "loadavg" in cmd:
            # carga crítica (4 CPUs)
            return ("15.20 14.80 13.50 8/342 12345", "", 0)
        elif "nproc" in cmd or "cpuinfo" in cmd:
            return ("4\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "", 0)
        elif "free -m" in cmd:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            7850        7710         50          22          90          80\n"  # RAM crítica
                "Swap:           2048        1900         148\n",  # Swap crítico
                "", 0,
            )
        elif "sensors" in cmd:
            return (
                "coretemp-isa-0000\n"
                # temp crítica
                "Package id 0:  +88.0°C  (high = +100.0°C, crit = +100.0°C)\n"
                "Core 0:        +87.0°C\n",
                "", 0,
            )
        elif "dmesg" in cmd and ("link is" in cmd or "carrier" in cmd or "nic link" in cmd):
            # 3 link downs → CRITICAL (checado ANTES do dmesg geral)
            return (
                "[Mon Nov 20 14:01:00 2023] eth0: Link is Down\n"
                "[Mon Nov 20 14:03:00 2023] eth0: Link is Down\n"
                "[Mon Nov 20 14:05:00 2023] eth0: Link is Down\n"
                "[Mon Nov 20 14:05:05 2023] eth0: Link is Up 1000Mbps Full Duplex\n",
                "", 0,
            )
        elif "dmesg" in cmd and "usb" not in cmd:
            return (
                "[Mon Nov 20 14:00:01 2023] kernel panic - not syncing: VFS: Unable to mount root fs\n"
                "[Mon Nov 20 14:01:05 2023] EXT4-fs error (device sda1): ext4 filesystem error\n"
                "[Mon Nov 20 14:02:00 2023] Out of memory: Kill process 1234 (apache2) score 900\n",
                "", 0,
            )
        elif "arp -n" in cmd or "ip neigh" in cmd:
            # 3 entradas incompletas → CRITICAL
            return (
                "Address                  HWtype  HWaddress           Flags Iface\n"
                "192.168.1.10                     (incomplete)                              eth0\n"
                "192.168.1.20                     (incomplete)                              eth0\n"
                "192.168.1.30                     (incomplete)                              eth0\n",
                "", 0,
            )
        elif "ip -s" in cmd:
            # 250 erros RX → CRITICAL
            return (
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether b8:27:eb:xx:xx:xx\n"
                "    RX: bytes  packets  errors  dropped missed  mcast\n"
                "    98765432   765432   250     80      0       0\n"
                "    TX: bytes  packets  errors  dropped carrier collsns\n"
                "    43210987   543210   0       0       0       0\n",
                "", 0,
            )
        elif "ping" in cmd:
            return (
                "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
                "10 packets transmitted, 8 received, 20% packet loss, time 9003ms\n",
                "", 0,
            )
        return _match_command(command)

    def _warning_outputs(self, command: str) -> Tuple[str, str, int]:
        """Simula sistema com avisos."""
        cmd = command.lower()

        if "df -h" in cmd:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        50G   42G  6.5G  87% /\n"  # aviso
                "/dev/sda2       100G   78G   18G  82% /data\n",  # aviso
                "", 0,
            )
        elif "systemctl" in cmd and "failed" in cmd:
            return (
                "  UNIT                    LOAD   ACTIVE SUB    DESCRIPTION\n"
                "● nginx.service           loaded failed failed  A high performance web server\n"
                "● postgresql.service      loaded failed failed  PostgreSQL RDBMS\n"
                "\nLEGEND: UNIT - service; LOAD - load state; ACTIVE - active state\n",
                "", 0,
            )
        elif "free -m" in cmd:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            7850        6800         150         200         900         720\n"  # alta
                "Swap:           2048        1200         848\n",  # swap em uso
                "", 0,
            )
        elif "usb" in cmd and "dmesg" in cmd:
            # Múltiplas desconexões USB
            disconnects = "\n".join(
                f"[Mon Nov 20 14:{i:02d}:00 2023] usb 1-1.2: USB disconnect, device number 4"
                for i in range(8)
            )
            return (disconnects, "", 0)
        elif "dmesg" in cmd and ("link is" in cmd or "carrier" in cmd or "nic link" in cmd):
            # 2 link downs → WARNING
            return (
                "[Mon Nov 20 14:01:00 2023] eth0: Link is Down\n"
                "[Mon Nov 20 14:01:05 2023] eth0: Link is Up 1000Mbps Full Duplex\n"
                "[Mon Nov 20 14:03:00 2023] eth0: Link is Down\n"
                "[Mon Nov 20 14:03:05 2023] eth0: Link is Up 1000Mbps Full Duplex\n",
                "", 0,
            )
        elif "arp -n" in cmd or "ip neigh" in cmd:
            # 2 entradas incompletas → WARNING
            return (
                "Address                  HWtype  HWaddress           Flags Iface\n"
                "192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C     eth0\n"
                "192.168.1.10                     (incomplete)                              eth0\n"
                "192.168.1.20                     (incomplete)                              eth0\n",
                "", 0,
            )
        elif "ip -s" in cmd:
            # 30 erros RX → WARNING
            return (
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether b8:27:eb:xx:xx:xx\n"
                "    RX: bytes  packets  errors  dropped missed  mcast\n"
                "    98765432   765432   30      200     0       0\n"
                "    TX: bytes  packets  errors  dropped carrier collsns\n"
                "    43210987   543210   0       0       0       0\n",
                "", 0,
            )
        elif "ping" in cmd:
            return (
                "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
                "10 packets transmitted, 9 received, 10% packet loss, time 9003ms\n",
                "", 0,
            )
        return _match_command(command)
