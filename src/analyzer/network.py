"""
Network Analyzers
=================
Analisadores de conectividade de rede: ARP incompleto, erros de interface,
eventos de link (flapping) e perda de pacotes ao gateway.
"""

import logging
import re

from src.collector.system_collector import SystemData
from src.analyzer.models import Severity, Issue, DiagnosticResult, _has_output

logger = logging.getLogger(__name__)


def analyze_arp(data: SystemData, result: DiagnosticResult) -> None:
    """Detecta entradas ARP '(incomplete)' que indicam dispositivos inacessíveis."""
    if not _has_output(data.arp_table):
        return

    incomplete = [
        line for line in data.arp_table.stdout.splitlines()
        if "(incomplete)" in line.lower()
    ]
    if not incomplete:
        return

    count = len(incomplete)
    ips = [line.split()[0] for line in incomplete if line.split()]
    ip_list = ", ".join(ips)
    severity = Severity.CRITICAL if count > 2 else Severity.WARNING

    result.issues.append(Issue(
        severity=severity,
        category="Rede",
        title=f"ARP incompleto: {count} dispositivo(s) inacessível(is)",
        description=(
            f"{count} entrada(s) ARP marcada(s) como '(incomplete)': {ip_list}. "
            "Entrada incompleta significa que o host enviou um ARP request mas "
            "não obteve resposta — o dispositivo está inacessível no momento "
            "ou desconectou da rede. Pode indicar falha intermitente de "
            "conectividade, endereço IP duplicado ou dispositivo em estado de sleep."
        ),
        recommendation=(
            "1. Verifique a conexão física do dispositivo. "
            "2. Force resolução ARP: arping -I eth0 -c 5 <IP>. "
            "3. Limpe e re-teste: arp -d <IP> && ping -c 1 <IP>. "
            "4. Detecte IP duplicado: arping -D -I eth0 <IP>. "
            "5. Capture em tempo real: tcpdump -i eth0 arp."
        ),
        raw_evidence="\n".join(incomplete),
    ))


def analyze_network_interface_errors(data: SystemData, result: DiagnosticResult) -> None:
    """Detecta erros e drops nas interfaces de rede via 'ip -s link'."""
    if not _has_output(data.network_stats):
        return

    issues = []
    current_iface = None
    rx_mode = tx_mode = False

    for line in data.network_stats.stdout.splitlines():
        stripped = line.strip()

        m = re.match(r"^\d+:\s+(\S+?)[@:]", line)
        if m:
            current_iface = m.group(1)
            rx_mode = tx_mode = False
            continue

        if not current_iface:
            continue

        if stripped.startswith("RX:"):
            rx_mode, tx_mode = True, False
            continue

        if stripped.startswith("TX:"):
            rx_mode, tx_mode = False, True
            continue

        if not (rx_mode or tx_mode):
            continue

        if not (stripped and stripped[0].isdigit()):
            continue

        vals = stripped.split()
        if len(vals) < 4:
            rx_mode = tx_mode = False
            continue

        try:
            errors = int(vals[2])
            dropped = int(vals[3])
        except (ValueError, IndexError):
            rx_mode = tx_mode = False
            continue

        direction = "RX" if rx_mode else "TX"
        rx_mode = tx_mode = False

        if errors > 0:
            severity = Severity.CRITICAL if errors >= 100 else Severity.WARNING
            issues.append(Issue(
                severity=severity,
                category="Rede",
                title=f"Erros {direction} em {current_iface}: {errors} erro(s)",
                description=(
                    f"Interface {current_iface} apresenta {errors} erro(s) de "
                    f"{'recepção' if direction == 'RX' else 'transmissão'}. "
                    "Erros indicam pacotes corrompidos ou descartados na camada de link. "
                    "Causas: cabo defeituoso, duplex mismatch ou NIC com problemas."
                ),
                recommendation=(
                    f"1. Inspecione o cabo e conector de {current_iface}. "
                    "2. Verifique e fixe o duplex: ethtool -s eth0 duplex full. "
                    f"3. Estatísticas detalhadas: ethtool -S {current_iface}. "
                    f"4. Acompanhe em tempo real: watch -n 1 'ip -s link show {current_iface}'."
                ),
                raw_evidence=f"{direction} errors={errors} dropped={dropped} [{current_iface}]",
            ))

        if dropped >= 50:
            issues.append(Issue(
                severity=Severity.WARNING,
                category="Rede",
                title=f"Drops {direction} em {current_iface}: {dropped} pacote(s)",
                description=(
                    f"Interface {current_iface} descartou {dropped} pacote(s) na "
                    f"direção {direction}. "
                    "Drops elevados indicam sobrecarga de buffer ou congestionamento."
                ),
                recommendation=(
                    "1. Verifique carga de CPU e uso de memória. "
                    f"2. Ajuste buffer: ethtool -G {current_iface} rx 4096. "
                    "3. Monitore tráfego: iftop."
                ),
                raw_evidence=f"{direction} errors={errors} dropped={dropped} [{current_iface}]",
            ))

    result.issues.extend(issues)


def analyze_network_link_events(data: SystemData, result: DiagnosticResult) -> None:
    """Detecta eventos de link down/up (link flapping) no dmesg filtrado."""
    if not _has_output(data.dmesg_network):
        return

    link_down_lines = [
        line for line in data.dmesg_network.stdout.splitlines()
        if re.search(
            r"(link is down|NIC link is down|carrier lost|link failure)",
            line, re.IGNORECASE
        )
    ]
    if not link_down_lines:
        return

    count = len(link_down_lines)
    all_events = [
        line for line in data.dmesg_network.stdout.splitlines()
        if re.search(r"(link is (up|down)|carrier (lost|found))", line, re.IGNORECASE)
    ]
    severity = Severity.CRITICAL if count > 2 else Severity.WARNING

    result.issues.append(Issue(
        severity=severity,
        category="Rede",
        title=f"Quedas de link detectadas: {count} evento(s) 'link down'",
        description=(
            f"{count} evento(s) de 'link down' detectado(s) no dmesg. "
            f"Total de eventos de link (up + down): {len(all_events)}. "
            "Quedas repetidas de link (link flapping) indicam instabilidade física: "
            "cabo frouxo, switch com problema, NIC com defeito ou driver instável."
        ),
        recommendation=(
            "1. Inspecione a conexão física do cabo de rede. "
            "2. Verifique logs completos: dmesg -T | grep -iE 'link|carrier'. "
            "3. Teste com outro cabo e/ou outra porta do switch. "
            "4. Verifique a versão do driver: ethtool -i eth0. "
            "5. Monitore em tempo real: journalctl -kf | grep -i link."
        ),
        raw_evidence="\n".join(link_down_lines[:20]),
    ))


def analyze_gateway_connectivity(data: SystemData, result: DiagnosticResult) -> None:
    """Detecta perda de pacotes no ping ao gateway padrão."""
    if not _has_output(data.ping_gateway):
        return

    output = data.ping_gateway.stdout

    if "gateway nao encontrado" in output.lower() or "not found" in output.lower():
        result.issues.append(Issue(
            severity=Severity.WARNING,
            category="Rede",
            title="Gateway padrão não encontrado",
            description="Nenhuma rota padrão configurada ou gateway inacessível.",
            recommendation=(
                "Verifique a configuração de rede: ip route show. "
                "Certifique-se de que a interface está UP e com IP configurado."
            ),
            raw_evidence=output[:200],
        ))
        return

    m = re.search(r"(\d+)%\s+packet loss", output)
    if not m:
        return

    loss = int(m.group(1))
    if loss == 0:
        return

    gw_match = re.search(r"PING\s+\S+\s+\((\S+?)\)", output)
    gw = gw_match.group(1) if gw_match else "gateway"
    severity = Severity.CRITICAL if loss > 10 else Severity.WARNING

    result.issues.append(Issue(
        severity=severity,
        category="Rede",
        title=f"Perda de pacotes ao gateway {gw}: {loss}%",
        description=(
            f"{loss}% de perda de pacotes detectada no ping ao gateway {gw}. "
            "Perda de pacotes indica instabilidade na rota: congestionamento, "
            "cabo com ruído, switch sobrecarregado ou interferência (Wi-Fi)."
        ),
        recommendation=(
            f"1. Teste prolongado: ping -c 100 {gw}. "
            "2. Trace a rota: traceroute -n <gateway> ou mtr --report <gateway>. "
            "3. Verifique erros na interface: ip -s link show eth0. "
            "4. Em redes Wi-Fi: verifique sinal e canal (iwconfig, iw dev)."
        ),
        raw_evidence=output[-300:],
    ))
