import argparse
import logging
import os
import sys
import time

from sniff_and_trace import run

log_levels = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

templates = {
    'light': 'plotly_white',
    'dark': 'plotly_dark'
}


def main():
    parser = argparse.ArgumentParser(description='Map traces')

    parser.add_argument('-p', '--projection', type=str, default='equirectangular', help='type of map projection')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='traceroute timeout')
    parser.add_argument('-d', '--duration', type=int, default=60, help='amount of seconds to track traffic')
    parser.add_argument('-l', '--log-level', type=str, default='info',
                        help="log level, one of: 'debug', 'info', 'warning', 'error', 'critical'")
    parser.add_argument('-m', '--mode', type=str, default='light', help="display mode, one of: 'light', 'dark'")

    parser.add_argument('--display-name', action='store_true', help='display names of traces')
    parser.add_argument('--clean', action='store_true',
                        help='clear cache of ip latitudes and longitudes and look them up again')

    args = parser.parse_args()

    if not os.path.isdir('logs'):
        os.makedirs('logs')
    logging.basicConfig(filename=f'logs/{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=log_levels[args.log_level])

    run(projection_type=args.projection, timeout=args.timeout, duration=args.duration, clean=args.clean,
        display_name=args.display_name, template=templates[args.mode])


if __name__ == '__main__':
    main()
