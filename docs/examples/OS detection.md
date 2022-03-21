```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.os(),
    NMAP.osscan_guess(),
    NMAP.osscan_limit()
)
```

```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.os(
        NMAP.osscan_guess(),
        NMAP.osscan_limit()
    )
)
```

```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.os_detection(
        NMAP.osscan_guess(),
    ),
    NMAP.osscan_limit()
)
```
