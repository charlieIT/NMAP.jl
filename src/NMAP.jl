"""
A Julia interface to [nmap](https://nmap.org/) that allows scan and output manipulation

NMAP.jl aims to provide developers with idiomatic nmap bindings to aid the creation of security audit tools

## Scanner

## Scan

## run!

## Examples

**Create scanners**

Example command: `nmap localhost 127.0.0.1 scanme.nmap.org -p 21-25,80,443,8080 -sV -O -sC --packet-trace -T0`
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

**Execute a scan**
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
    include("scan.jl")
    include("scanner.jl")
    include("options.jl")
    #include("methods.jl")

end
