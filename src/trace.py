import ipaddress
import json
import logging
import urllib.request
from typing import Optional, Tuple

import plotly.graph_objects as go
from scapy.layers.inet import traceroute
from scapy.layers.inet6 import traceroute6

ip_locations = {}
blacklisted_ips = set()

marker_size = 10
max_ttl_traceroute = 32


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
            if lat == 'Not found' or lon == 'Not found' or lat is None or lon is None:
                blacklisted_ips.add(ip_addr)
                return None
            else:
                ip_locations[ip_addr] = lat, lon
                return lat, lon
    except Exception as e:
        logging.error(f'Error getting location of {ip_addr}: {e}')
        return None


def trace(ip: str, timeout: int) -> go.Scattergeo:
    if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        ans, err = traceroute6(ip, maxttl=max_ttl_traceroute, dport=53, verbose=False, timeout=timeout)
    else:
        ans, err = traceroute(ip, maxttl=max_ttl_traceroute, dport=53, verbose=False, timeout=timeout)

    lats, lons, text = [], [], []
    msg = f'Route to {ip}: '
    for sent_ip, received_ip in ans.res:
        res = get_lat_lon(received_ip.src)
        if res is not None:
            lat, lon = res[0], res[1]
            lats += [lat]
            lons += [lon]
            text += [received_ip.src]
            msg += f'{sent_ip.dst} [{lat}, {lon}], '

    if len(lats) == 0:
        res = get_lat_lon(ip)
        if res is not None:
            lat, lon = res[0], res[1]
            lats += [lat]
            lons += [lon]
            text += [received_ip.src]

    logging.info(msg)
    if len(lats) == 1:
        return go.Scattergeo(mode='markers', lon=lons, lat=lats, text=[],
                             marker={'size': marker_size, 'symbol': 'square'})
    else:
        return go.Scattergeo(mode='markers+lines', lon=lons, lat=lats, text=[],
                             marker={'size': marker_size, 'symbol': 'square'})
