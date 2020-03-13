import time
from argparse import Namespace

import plotly.graph_objects as go

from src.sniff import SniffThread
from src.trace import trace

update_interval = 5


def sniff_and_trace(args: Namespace):
    fig = go.Figure(go.Scattergeo())
    fig.update_geos(projection_type=args.projection, visible=True, resolution=110, showcountries=True,
                    countrycolor="Black")
    fig.update_layout(margin={'l': 0, 't': 30, 'b': 0, 'r': 0})

    sniff_thread = SniffThread(args.duration)
    sniff_thread.start()

    duration = args.duration
    total_minutes, total_seconds = divmod(duration, 60)
    print(f'Tracking for {total_minutes:02d}:{total_seconds:02d} ({duration} sec)')

    for i in range(duration, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Remaining: {minutes:02d}:{seconds:02d} [unique source ips sniffed: {len(sniff_thread.seen_sources)},'
              f' total: {sniff_thread.sniffed}]', end='\r')
        time.sleep(1)
    print('')

    count = 1
    for ip in sniff_thread.seen_sources:
        print(f'Calculating traces...                  [{count}/{len(sniff_thread.seen_sources)}]', end='\r')
        fig.add_trace(trace(ip, args.timeout))
        count += 1

    if count > 1:
        print(f'Calculating traces...Done              [{count - 1}/{len(sniff_thread.seen_sources)}]')
    else:
        print('No traces!')

    fig.update_layout(title=f'Traceroute{"s" if count > 1 else ""} of {count} trace{"s" if count > 1 else ""}')
    fig.show()
