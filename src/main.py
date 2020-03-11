import ipaddress
import logging
import urllib.request
import json
import time
from threading import Thread
from typing import Optional, Tuple

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet

import plotly.graph_objects as go
import plotly.express as px

seen_global_ips = set()
recent_ips = set()
update_interval = 5

ip_locations = {}
blacklisted_ips = set()

global fig


def get_lat_lon(ip: str) -> Optional[Tuple[float, float]]:
    if ip in blacklisted_ips:
        return None
    elif ip in ip_locations:
        return ip_locations[ip]

    with urllib.request.urlopen(f"https://geolocation-db.com/json/{ip}") as url:
        json_data = json.loads(url.read().decode())

        if 'latitude' not in json_data or 'longitude' not in json_data:
            blacklisted_ips.add(ip)
            return None

        lat, lon = [json_data['latitude']], [json_data['longitude']]
        if lat == 'Not found' or lon == 'Not found':
            blacklisted_ips.add(ip)
            return None
        else:
            ip_locations[ip] = lat, lon
            return lat[0], lon[0]


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
                lat, lon = res[0], res[1]
                logging.info(msg=f"{ip} at {lat},{lon}")

                lats += [lat]
                lons += [lon]

        # print(ip_set_data)
        fig.add_trace(go.Scattermapbox(mode="markers", lon=lons, lat=lats, marker={'size': 10}))
        fig.update_layout()


def dns_display(pkt: Packet):
    if not pkt.haslayer(IP):
        return

    dst = pkt[IP].dst
    if not ipaddress.ip_address(dst).is_global:
        return
    elif dst in seen_global_ips:
        return

    seen_global_ips.add(dst)
    recent_ips.add(dst)

    if len(seen_global_ips) % update_interval == 0:
        add_fig = AddFig(recent_ips)
        add_fig.run()

        recent_ips.clear()


if __name__ == '__main__':
    logging.basicConfig(filename=f'{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=logging.INFO)

    fig = px.scatter_geo()
    fig.update_layout(margin={'l': 1, 't': 1, 'b': 1, 'r': 1}, mapbox={'style': "open-street-map", })
    fig.show()

    sniff(prn=dns_display)
