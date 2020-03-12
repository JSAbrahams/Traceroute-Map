import ipaddress
import json
import logging
import threading
import time
import urllib.request
from copy import deepcopy
from threading import Thread
from typing import Optional, Tuple

import plotly.graph_objects as go
from scapy.all import sniff
from scapy.layers.inet import IP, traceroute
from scapy.packet import Packet

seen_global_ips = set()
recent_ips = set()
update_interval = 5

ip_locations = {}
blacklisted_ips = set()

global fig


class StoppableThread(Thread):
    _stop_event = threading.Event()

    def __init__(self,  *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


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


class AddFig(StoppableThread):
    def __init__(self, ips: [str]):
        Thread.__init__(self)
        self.ips = ips

    def run(self) -> None:
        global fig

        for ip in self.ips:
            if self.stopped():
                return

            lats, lons = [], []
            ans, err = traceroute(ip, maxttl=32, verbose=False)
            msg = f'Route to {ip}: '

            for traced_ip in ans.get_trace():
                res = get_lat_lon(traced_ip)
                if res is not None:
                    lat, lon = res[0], res[1]
                    lats += [lat]
                    lons += [lon]
                    msg += f'{traced_ip} [{lat}, {lon}], '

            logging.info(msg)
            if len(lats) == 1:
                fig.add_trace(go.Scattergeo(mode='markers', lon=lons, lat=lats, marker={'size': 10}))
            elif len(lats) > 1:
                fig.add_trace(go.Scattergeo(mode='markers+lines', lon=lons, lat=lats, marker={'size': 10}))


class SniffThread(StoppableThread):
    def __init__(self):
        Thread.__init__(self)
        self.threads = []

    def dns_display(self, pkt: Packet):
        if not pkt.haslayer(IP):
            return

        dst = pkt[IP].dst
        if not ipaddress.ip_address(dst).is_global or dst in seen_global_ips:
            return

        seen_global_ips.add(dst)
        recent_ips.add(dst)

        if len(seen_global_ips) % update_interval == 0:
            add_fig = AddFig(deepcopy(recent_ips))
            self.threads += [add_fig]
            add_fig.start()
            recent_ips.clear()

    def stop(self):
        for thread in self.threads:
            thread.stop()

    def run(self) -> None:
        while not self.stopped():
            sniff(count=100, prn=self.dns_display)


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
    sniff_thread = SniffThread()
    sniff_thread.start()

    for i in range(sleep_amount, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Remaining: {minutes:02d}:{seconds:02d}', end='\r')
        time.sleep(1)
    print('')

    print('Waiting for threads to stop...')
    sniff_thread.stop()
    sniff_thread.join()

    print('Done!')
    fig.show()
