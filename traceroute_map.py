import argparse
import logging
import time

from src.sniff_and_trace import sniff_and_trace

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Map traces')

    parser.add_argument('-p', '--projection', type=str, default='equirectangular', help='Type of map projection')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='traceroute timeout')
    parser.add_argument('-d', '--duration', type=int, default=20, help='Duration for tracking traffic')

    logging.basicConfig(filename=f'{time.strftime("%Y-%m-%d-%H%M%S")}.log', level=logging.INFO)
    
    sniff_and_trace(parser.parse_args())
