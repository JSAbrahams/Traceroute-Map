import ipaddress
import logging
from threading import Thread
from typing import Set

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


class SniffThread(Thread):
    def __init__(self, duration: int):
        Thread.__init__(self)
        self.sniffed: int = 0
        self.duration = duration
        self.seen_sources: Set[str] = set()

    def store_ip(self, pkt: Packet):
        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return

        self.sniffed += 1
        src = pkt[IP].src
        if ipaddress.ip_address(src).is_global and src not in self.seen_sources:
            self.seen_sources.add(src)
            logging.info(f'Sniffed source: {src} -> {pkt[IP].dst}')

    def run(self) -> None:
        sniff(prn=self.store_ip, timeout=self.duration)
