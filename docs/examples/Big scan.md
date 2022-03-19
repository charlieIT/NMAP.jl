```julia
scanner = NMAP.Scanner(
    NMAP.targets("127.0.0.1", "localhost", "192.168.80.1-255", "scanme.nmap.org"),
    NMAP.ports("21-25", "80-443", "27017", "8080", "9000"),
    NMAP.spoof_source("192.168.80.2"),
    NMAP.service_info(
        NMAP.version_all()
    ),
    NMAP.os_detection(
        NMAP.osscan_limit()
    ),
    NMAP.script("vulnscan/vulnscan"), #use NMAP.script("default") you do not have vulnscan locally
    NMAP.only_open(),
    NMAP.verbose(2), #-vv
    NMAP.dd() #-dd
)
```