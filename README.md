# Traceroute Map

See the paths all your packets took as your browse the internet at a leisurely pace.
In addition to the ip addresses, we make use of traceroute to iteratively discover how this packet was (likely) routed
from you to said server (or vice-versa, depending on how you look at it).

We use make use of https://geolocation-db.com/ to get latitude and longitude of IP addresses.

## Usage

    traceroute_map.py [-h] [-p PROJECTION] [-t TIMEOUT] [-d DURATION]
                         [--clean]

    Map traces

    optional arguments:
      -h, --help            show this help message and exit
      -p PROJECTION, --projection PROJECTION
                            type of map projection
      -t TIMEOUT, --timeout TIMEOUT
                            traceroute timeout
      -d DURATION, --duration DURATION
                            amount of seconds to track traffic
      -l LOG_LEVEL, --log-level LOG_LEVEL
                            log level, on of: 'debug', 'info', 'warning', 'error',
                            'critical'
      --display-name        display names of traces
      --clean               clear cache of ip latitudes and longitudes and look
                            them up again

## Output

Aside from the graphical overview, we also output a `*.log` file with all the IP addresses and their geographical
locations in latitude and longitude format.

Note that all IP's for which we cannot find a location are discarded.
