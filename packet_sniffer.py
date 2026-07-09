"""
capture/packet_sniffer.py
--------------------------
This is the "eyes" of the NIDS. It uses Scapy to grab packets straight
off your network card and pulls out the fields we care about
(source IP, destination IP, port, protocol, size, TCP flags).

Beginner notes on Scapy:
- Scapy lets Python read raw network packets, something your OS
  normally hides from regular programs.
- Reading raw packets requires Administrator/root privileges, because
  it's a low-level operation. See the README for how to run this.
- `sniff()` is Scapy's main function: it listens on an interface and
  calls a function (a "callback") every time a packet arrives.

Every parsed packet is handed to a callback function that main.py
supplies, so this file doesn't need to know anything about detection
or alerting - it just captures and describes packets. This separation
(capture vs. detection vs. alerting) is a common, clean way to design
a pipeline: each piece does one job.
"""
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP

from utils.logger import get_logger

logger = get_logger("Sniffer")


def parse_packet(packet):
    """
    Turn a raw Scapy packet into a plain Python dictionary that the
    rest of our program can easily work with, regardless of whether
    it came from a live interface or a saved .pcap file.

    Returns None for packets we don't care about (non-IP traffic).
    """
    if IP not in packet:
        return None

    record = {
        "timestamp": time.time(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "size": len(packet),
        "flags": None,
    }

    if TCP in packet:
        record["protocol"] = "TCP"
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        # TCP flags tell us things like "this is a connection attempt" (SYN)
        # Scapy exposes them as a string like 'S', 'SA', 'F', 'PA', etc.
        record["flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        record["protocol"] = "UDP"
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        record["protocol"] = "ICMP"
    else:
        record["protocol"] = "OTHER"

    return record


class PacketSniffer:
    """
    Wraps Scapy's sniff() function. Call start() with a callback that
    accepts one parsed-packet dictionary at a time.
    """

    def __init__(self, interface=None, bpf_filter="ip"):
        self.interface = interface
        # bpf_filter uses Berkeley Packet Filter syntax to only capture
        # what we want at the OS level (much faster than filtering in
        # Python after the fact). "ip" = only IPv4 traffic.
        self.bpf_filter = bpf_filter

    def start(self, on_packet_callback, packet_count=0):
        """
        Begin sniffing. packet_count=0 means "run forever until Ctrl+C".
        on_packet_callback receives each parsed packet dict.
        """
        logger.info(
            f"Starting capture on interface={self.interface or 'default'} "
            f"filter='{self.bpf_filter}'"
        )

        def _handle(pkt):
            record = parse_packet(pkt)
            if record:
                on_packet_callback(record)

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=_handle,
                store=False,       # don't keep packets in memory, we handle them live
                count=packet_count,
            )
        except PermissionError:
            logger.error(
                "Permission denied. Packet capture needs admin/root privileges. "
                "See README section 'Running the sniffer'."
            )
            raise
