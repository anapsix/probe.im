PROBE.im
========

[Probe.im](http://probe.im/ping?json=1) is a simple "scan me" type service.  
It pings you back and displays your latency or scans requested port and reports it's status (closed, filtered, opened).

#### Usage Example

    /ping         returns latency in _ms_, or "0.0" if unreachable
    /scan/80      returns status of *port* 80/tcp as opened, filtered or closed
    /scan/80/tcp  returns status of *port* 80/tcp as opened, filtered or closed

> Add `?json=1` for JSON output
