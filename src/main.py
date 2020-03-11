from threading import Thread

from ipwhois import IPWhois
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet
import plotly.graph_objects as go

blacklisted_ips = set()
all_ips = set()
recent_ips = set()

update_interval = 5

ip_locations = {}

global fig


class AddFig(Thread):
    def __init__(self, ips: [str]):
        Thread.__init__(self)
        self.ips = ips

    def run(self) -> None:
        global fig

        for ip in self.ips:
            ip_whois = IPWhois(ip)
            lookup = ip_whois.lookup_whois()
            print(lookup)
            for net in lookup['nets']:
                print(net)


def is_invalid_ip(ip: str) -> bool:
    return False


def dns_display(pkt: Packet):
    if not pkt.haslayer(IP):
        return

    dst = pkt[IP].dst
    if dst in blacklisted_ips:
        return
    elif is_invalid_ip(dst):
        blacklisted_ips.add(element=dst)
        return

    if dst not in all_ips:
        all_ips.add(dst)
        recent_ips.add(dst)

        if len(all_ips) % update_interval == 0:
            add_fig = AddFig(recent_ips)
            add_fig.run()

            recent_ips.clear()


if __name__ == '__main__':
    # fig = go.Figure()
    # fig.show()

    sniff(prn=dns_display, filter='DNS')
