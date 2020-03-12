import ipaddress
import json
import logging
import sys
import threading
import time
import urllib.request
from threading import Thread
from typing import Optional, Tuple

import plotly.graph_objects as go
from scapy.all import sniff
from scapy.layers.inet import IP, traceroute
from scapy.layers.inet6 import traceroute6
from scapy.packet import Packet

seen_sources = set()

ip_locations = {}
blacklisted_ips = set()

default_track_duration = 20
update_interval = 5
marker_size = 10
max_track_time = 300
max_ttl_traceroute = 32
traceroute_timeout = 1

global fig


class StoppableThread(Thread):
    _stop_event = threading.Event()

    def __init__(self, *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


def get_lat_lon(ip_addr: str) -> Optional[Tuple[float, float]]:
    if ip_addr in blacklisted_ips:
        return None
    elif ip_addr in ip_locations:
        return ip_locations[ip_addr]

    try:
        with urllib.request.urlopen(f'https://geolocation-db.com/json/{ip_addr}') as url:
            json_data = json.loads(url.read().decode())
            if 'latitude' not in json_data or 'longitude' not in json_data:
                blacklisted_ips.add(ip_addr)
                return None

            lat, lon = json_data['latitude'], json_data['longitude']
            if lat == 'Not found' or lon == 'Not found':
                blacklisted_ips.add(ip_addr)
                return None
            else:
                ip_locations[ip_addr] = lat, lon
                return lat, lon
    except Exception as e:
        logging.error(f'Error getting location of {ip_addr}: {e}')
        return None


def dns_display(pkt: Packet):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    if not ipaddress.ip_address(src).is_global or src in seen_sources:
        return

    seen_sources.add(src)
    logging.info(f'Sniffed source: {src} -> {pkt[IP].dst}')


class SniffThread(StoppableThread):
    def __init__(self):
        Thread.__init__(self)

    def run(self) -> None:
        while not self.stopped():
            sniff(count=100, prn=dns_display)


if __name__ == '__main__':
    print("Traceroute Map: See where all those packets come from")

    fig = go.Figure(go.Scattergeo())
    fig.update_geos(visible=True, resolution=110, showcountries=True, countrycolor="Black")
    fig.update_layout(margin={'l': 0, 't': 30, 'b': 0, 'r': 0})

    while True:
        if len(sys.argv) >= 2:
            sleep_amount = int(sys.argv[1])
        else:
            sleep_amount = default_track_duration

        if sleep_amount <= 0:
            print("Amount must be greater than 0")
            continue
        elif sleep_amount > max_track_time:
            print(f"Amount must be {max_track_time} or less")
            continue
        break

    logging.basicConfig(filename=f'{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=logging.INFO)
    sniff_thread = SniffThread()
    sniff_thread.start()

    total_minutes, total_seconds = divmod(sleep_amount, 60)
    for i in range(sleep_amount, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Tracking for {total_minutes:02d}:{total_seconds:02d} ({sleep_amount} sec), '
              f'remaining: {minutes:02d}:{seconds:02d} '
              f'[unique source ips sniffed: {len(seen_sources)}]', end='\r')
        time.sleep(1)
    print('')

    print('Waiting for sniffing to stop...', end='')
    sniff_thread.stop()
    sniff_thread.join()
    print(f'Done           [total sniffed: {len(seen_sources)}]')

    count = 1
    for ip in seen_sources:
        print(f'Calculating traces...                         [{count}/{len(seen_sources)}]', end='\r')
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
            ans, err = traceroute6(ip, maxttl=max_ttl_traceroute, dport=53, verbose=False, timeout=traceroute_timeout)
        else:
            ans, err = traceroute(ip, maxttl=max_ttl_traceroute, dport=53, verbose=False, timeout=traceroute_timeout)

        lats, lons = [], []
        msg = f'Route to {ip}: '
        for sent_ip, received_ip in ans.res:
            res = get_lat_lon(received_ip.src)
            if res is not None:
                lat, lon = res[0], res[1]
                lats += [lat]
                lons += [lon]
                msg += f'{sent_ip.dst} [{lat}, {lon}], '

        logging.info(msg)
        if len(lats) == 1:
            fig.add_trace(go.Scattergeo(mode='markers', lon=lons, lat=lats, marker={'size': marker_size}))
        elif len(lats) > 1:
            fig.add_trace(go.Scattergeo(mode='markers+lines', lon=lons, lat=lats, marker={'size': marker_size}))

        if count == len(seen_sources):
            print(f'Calculating traces...Done                     [{count}/{len(seen_sources)}]')
        count += 1

    fig.show()
