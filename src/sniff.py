import ipaddress
import logging
from threading import Thread
from typing import Dict

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


class SniffThread(Thread):
    def __init__(self, duration: int):
        Thread.__init__(self)
        self.sniffed: int = 0
        self.duration = duration
        self.seen_sources: Dict[str, int] = {}

    def store_ip(self, pkt: Packet):
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        if not ipaddress.ip_address(src).is_global:
            return

        self.sniffed += 1
        if src not in self.seen_sources:
            self.seen_sources[src] = 1
            logging.info(f'Sniffed source: {src} -> {dst}')
        else:
            self.seen_sources[src] = self.seen_sources[src] + 1

    def run(self) -> None:
        sniff(prn=self.store_ip, timeout=self.duration)
