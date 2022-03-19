`nmap localhost -sV`
```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.service_info()
)
```

`nmap localhost -sV --version-intensity 2`
```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.service_info(),
    NMAP.version_intensity(2)
)
```

`nmap localhost -sV --version-intensity 9 --version-trace`
```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.service_info(),
    NMAP.version_all(),
    NMAP.version_trace()
)
```

`nmap localhost -sV --version-intensity 2 --version-trace`
```julia
scanner = Scanner(
    NMAP.targets("localhost"),
    NMAP.service_info(
        NMAP.version_light()
    ),
    NMAP.version_trace()
)
```
