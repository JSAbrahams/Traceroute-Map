import time
from argparse import Namespace

import plotly.graph_objects as go

from src.sniff import SniffThread
from src.trace import Trace

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
    print(f'Tracking for {total_minutes:02d}:{total_seconds:02d} ({duration:,} sec)')

    for i in range(duration, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Remaining: {minutes:02d}:{seconds:02d} [unique source ips sniffed: {len(sniff_thread.seen_sources):,},'
              f' total: {sniff_thread.sniffed:,},'
              f' bytes: {sniff_thread.total_bytes:,}]', end='\r')
        time.sleep(1)
    print('')

    count = 1
    trace = Trace()
    if not args.clean:
        trace.read_from_file()

    for ip, (hits, byte_count) in sniff_thread.seen_sources.items():
        print(f'Calculating traces...                  [{count}/{len(sniff_thread.seen_sources)}]', end='\r')
        fig.add_trace(trace.trace(ip, hits, byte_count, args.timeout))
        count += 1

    trace.write_to_file()

    if count > 1:
        print(f'Calculating traces...Done              [{count - 1}/{len(sniff_thread.seen_sources)}]')
    else:
        print('No traces!')

    fig.update_layout(title=f'Traceroute{"s" if count > 1 else ""} of {count:,} trace{"s" if count > 1 else ""}:'
                            f'{sniff_thread.total_bytes:,} bytes during {duration:,} seconds '
                            f'({total_minutes:02d}:{total_seconds:02d})')
    fig.show()
