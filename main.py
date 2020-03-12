import ipaddress
import json
import logging
import time
import urllib.request
from copy import deepcopy
from threading import Thread
from typing import Optional, Tuple

import plotly.graph_objects as go
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet

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

    try:
        with urllib.request.urlopen(f'https://geolocation-db.com/json/{ip}') as url:
            json_data = json.loads(url.read().decode())
            if 'latitude' not in json_data or 'longitude' not in json_data:
                blacklisted_ips.add(ip)
                return None

            lat, lon = json_data['latitude'], json_data['longitude']
            if lat == 'Not found' or lon == 'Not found':
                blacklisted_ips.add(ip)
                return None
            else:
                ip_locations[ip] = lat, lon
                return lat, lon
    except Exception as e:
        logging.error(f'Error getting location of {ip}: {e}')
        return None


class AddFig(Thread):
    def __init__(self, ips: [str]):
        Thread.__init__(self)
        self.ips = ips

    def run(self) -> None:
        global fig

        lats, lons = [], []
        for ip in self.ips:
            # route, unans = traceroute(ip, maxttl=32)
            # trace = route.get_trace()
            trace = [ip]
            msg = f'Route to {ip}: '

            for traced_ip in trace:
                res = get_lat_lon(traced_ip)
                if res is not None:
                    lat, lon = res[0], res[1]
                    lats += [lat]
                    lons += [lon]
                    msg += f'{traced_ip} [{lat}, {lon}], '

            if len(lats) > 0:
                map_box = go.Scattergeo(mode='markers', lon=lons, lat=lats, marker={'size': 10})
                fig.add_trace(map_box)
                logging.info(msg)


def dns_display(pkt: Packet):
    if not pkt.haslayer(IP):
        return

    dst = pkt[IP].dst
    if not ipaddress.ip_address(dst).is_global or dst in seen_global_ips:
        return

    seen_global_ips.add(dst)
    recent_ips.add(dst)

    if len(seen_global_ips) % update_interval == 0:
        add_fig = AddFig(deepcopy(recent_ips))
        add_fig.start()
        recent_ips.clear()


class SniffThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self) -> None:
        Thread(target=sniff(prn=dns_display)).run()


if __name__ == '__main__':
    print("Traceroute Map: See where all those packets come from")

    fig = go.Figure(go.Scattergeo())
    fig.update_geos(visible=True, resolution=110, showcountries=True, countrycolor="Black")
    fig.update_layout(margin={'l': 0, 't': 30, 'b': 0, 'r': 0})

    while True:
        sleep_amount = int(input("Amount of seconds to track <0, 120]: "))
        if sleep_amount <= 0:
            print("Amount must be greater than 0")
            continue
        elif sleep_amount > 120:
            print("Amount must be 120 or less")
            continue
        break

    logging.basicConfig(filename=f'{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=logging.INFO)
    SniffThread().start()

    for i in range(sleep_amount, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Remaining: {minutes:02d}:{seconds:02d}', end='\r')
        time.sleep(1)
    print('')

    fig.show()
