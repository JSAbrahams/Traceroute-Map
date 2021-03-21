import time

import plotly.graph_objects as go

from sniff_and_trace.sniff import SniffThread
from sniff_and_trace.trace import Trace

update_interval = 5


def run(projection_type: str, timeout: int, duration: int, clean: bool, display_name: bool, template: str):
    fig = go.Figure(go.Scattergeo())
    fig.update_geos(projection_type=projection_type, visible=True, resolution=110, showcountries=True,
                    countrycolor="Black")
    fig.update_layout(margin={'l': 0, 't': 30, 'b': 0, 'r': 0}, template=template)

    sniff_thread = SniffThread(duration)
    sniff_thread.start()

    total_minutes, total_seconds = divmod(duration, 60)
    print(f'Tracking for {total_minutes:02d}:{total_seconds:02d} ({duration:,} sec)')

    for i in range(duration, -1, -1):
        minutes, seconds = divmod(i, 60)
        print(f'Remaining: {minutes:02d}:{seconds:02d} [unique source ips sniffed: {len(sniff_thread.seen_sources):,},'
              f' total: {sniff_thread.sniffed:,},'
              f' {sniff_thread.total_bytes:,} bytes]', end='\r')
        time.sleep(1)
    print('')

    count = 1
    tracer = Trace()
    if not clean:
        tracer.read_from_file()

    for ip, (hits, byte_count) in sniff_thread.seen_sources.items():
        print(f'Calculating traces...                  [{count}/{len(sniff_thread.seen_sources)}]', end='\r')
        fig.add_trace(tracer.trace(ip, hits, byte_count, timeout, display_name))
        count += 1

    tracer.write_to_file()

    if count > 1:
        print(f'Calculating traces...Done              [{count - 1}/{len(sniff_thread.seen_sources)}]')
    else:
        print('No traces!')

    fig.update_layout(title=f'Traceroute of {count:,} trace{"s" if count > 1 else ""}:'
                            f'{sniff_thread.total_bytes:,} bytes ({sniff_thread.total_bytes}) '
                            f'during {duration:,} seconds ({total_minutes:02d}:{total_seconds:02d})')
    fig.show()
