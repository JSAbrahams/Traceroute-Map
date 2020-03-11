import ipaddress
import urllib.request
import json
from threading import Thread
from typing import Optional, Tuple

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet
import plotly.graph_objects as go

all_ips = set()
recent_ips = set()

update_interval = 5

ip_locations = {}
# blacklist ips which have no lat and lon
blacklisted_ips = set()

global fig
fig_name = 'globe'


def get_lat_lon(ip: str) -> Optional[Tuple[float, float]]:
    if ip in blacklisted_ips:
        return None
    elif ip in ip_locations:
        return ip_locations[ip]

    with urllib.request.urlopen(f"https://geolocation-db.com/json/{ip}") as url:
        json_data = json.loads(url.read().decode())

        if 'latitude' in json_data and 'longitude' in json_data:
            ret = [json_data['latitude']], [json_data['longitude']]
            ip_locations[ip] = ret
            return ret
        else:
            blacklisted_ips.add(ip)
            return None


class AddFig(Thread):
    def __init__(self, ips: [str]):
        Thread.__init__(self)
        self.ips = ips

    def run(self) -> None:
        global fig

        lats, lons = [], []
        for ip in self.ips:
            res = get_lat_lon(ip)
            if res is not None:
                lats += [res[0]]
                lons += [res[1]]

        ip_set_data = go.Scattergeo(lat=lats, lon=lons, mode='lines', line=dict(width=2, color='blue'))
        print(ip_set_data)
        # fig.update_layout(data=ip_set_data, filename=fig_name, fileopt='extend')


def dns_display(pkt: Packet):
    if not pkt.haslayer(IP):
        return

    dst = pkt[IP].dst
    if not ipaddress.ip_address(dst).is_global:
        return

    if dst not in all_ips:
        all_ips.add(dst)
        recent_ips.add(dst)

        if len(all_ips) % update_interval == 0:
            add_fig = AddFig(recent_ips)
            add_fig.run()

            recent_ips.clear()


if __name__ == '__main__':
    fig = go.Figure()
    fig.show()

    sniff(prn=dns_display, filter='DNS')
