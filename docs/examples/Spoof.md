```julia
scanner = NMAP.Scanner(
    NMAP.targets("127.0.0.1", "localhost", "192.168.80.1-255", "scanme.nmap.org"),
    NMAP.ports("21-25", "80-443", "27017", "8080", "9000"),
    NMAP.spoof_source("192.168.80.2"),
    NMAP.decoy(
        "192.168.0.2", 
        "192.168.0.10", 
        "192.168.0.100",
        "127.0.0.10",
        "127.0.1.100",
        "ME"),
    NMAP.interface("eth0"),
    NMAP.os_detection()
)
```