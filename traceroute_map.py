import argparse
import logging
import time

from src.sniff_and_trace import sniff_and_trace

log_levels = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Map traces')

    parser.add_argument('-p', '--projection', type=str, default='equirectangular', help='Type of map projection')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='traceroute timeout')
    parser.add_argument('-d', '--duration', type=int, default=60, help='amount of seconds to track traffic')
    parser.add_argument('-l', '--log-level', type=str, default='info',
                        help="log level, on of: 'debug', 'info', 'warning', 'error', 'critical'")
    parser.add_argument('--clean', action='store_true',
                        help='clear cache of ip latitudes and longitudes and look them up again')

    args = parser.parse_args()
    logging.basicConfig(filename=f'{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=log_levels[args.log_level])
    sniff_and_trace(projection_type=args.projection, timeout=args.timeout, duration=args.duration, clean=args.clean)
