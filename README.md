# Traceroute GUI

See the paths all your packets took as your browse the internet at a leisurely pace.
In addition to the ip addresses, we make use of traceroute to iteratively discover how this packet was (likely) routed
from you to said server (or vice-versa, depending on how you look at it).

This is just for fun.
Perhaps it can help you to get a better sense of scale and a small peek behind the curtain of how the internet works
(kind of).

We use make use of https://geolocation-db.com/ to get latitude and longitude of IP addresses.

## Output

Aside from the graphical overview, we also output a `*.log` file with all the IP addresses and their geographical
locations in latitude and longitude format.

Note that all IP's for which we cannot find a location are discarded.
