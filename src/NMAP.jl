"""
NMAP library aims to provide idiomatic nmap bindings to aid the creation of security audit tools using Julia

## Scanner

## Scan

## run!

## Examples

Create scanners
```julia
scanner = NMAP.Scanner(
    NMAP.targets("localhost", "127.0.0.1", "scanme.nmap.org"),
    NMAP.ports("21-25", "80", "443", "8080"),
    NMAP.service_info(),
    NMAP.os_detection(),
    NMAP.default_script(),
    NMAP.packet_trace(),
    NMAP.timingtemplate(NMAP.paranoid))
```

Execute a scan
```
scan = NMAP.run!(scanner)
```
"""
module NMAP

    export Scan
    export Scanner

    using Dates
    using EzXML
    using JSON
    using Lazy: Lazy, @forward
    using Printf
    using Revise
    using StructTypes
    using XMLDict

    include("unmarshalling.jl")
    using .Marshalling: Marshalling, Marsh, Leaf, unmarshall
    include("xml.jl")
    include("scan.jl")
    include("options.jl")
    include("timing.jl")
    #include("methods.jl")

end
