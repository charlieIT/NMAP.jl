# NMAP.jl
[![CI](https://github.com/charlieIT/NMAP.jl/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/charlieIT/NMAP.jl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![XMLOutputVersion: 1.04](https://img.shields.io/badge/xmloutputversion-1.04-blue)]()
[![XMLOutputVersion: 1.05](https://img.shields.io/badge/xmloutputversion-1.05-blue)]()


A Julia interface to [nmap](https://nmap.org/) that allows scan and output manipulation

NMAP.jl is still under active development, changes are likely to occur until the first stable release

## What is nmap 
**Nmap**, short for *Network Mapper*, is a [free and open source](https://nmap.org/npsl/) utility for network discovery and security auditing.

Nmap provides users with a powerful and flexible set of features for probing computer networks and perform [host discovery](https://nmap.org/book/man-host-discovery.html), service and [operating system detection](https://nmap.org/book/man-os-detection.html). Nmap's features are also extensible through scripts - [Nmap scripting engine](https://nmap.org/book/man-nse.html) - that provide more advanced features and automate a wider variety of network tasks, such as vulnerability detection or improved service detection. There is as collection of documented scripts available under [nsedoc](https://nmap.org/nsedoc/scripts/).

[Read more](https://nmap.org/)
 
## Features

 - [x] Interface for defining and running nmap scans
 - [ ] Parse XML output
	 - [x] [XML](https://nmap.org/book/nmap-dtd.html) elements mapped to Julia structures
	 - [x] Parse externally generated xml files
	 - [ ] Incorporate all xml elements
- [ ] Universe of `nmap`'s native options
    - [x] String based options 
	- [ ] Enums and helpers for nmap options or flags
	    - [x] Time templates
	    - [x] TCP flags
	    - [ ] Port states
	    - [ ] OS families
- [ ] Documentation 
	- [x] Usage examples and docstrings
	- [x] Options documentation aligned with nmap's usage documentation
	- [ ] Additional examples (`docs/examples`)

### Roadmap
- [ ] Improve library tests
- [ ] Error handling
- [ ] Add package to Julia Registry
- [ ] Integration with CPE library 
 
 ## Examples

### Usage 
```julia
using NMAP

? NMAP
? NMAP.Scanner
? NMAP.Scan
```
**Define a Scanner**
```julia
scanner = NMAP.Scanner(
  NMAP.ports("22","80","443"),
  NMAP.targets("scanme.nmap.org"),
  NMAP.traceroute())
```
**Execute the scan**

Option `-oX` is automatically added to produce XML output
```julia
scan = NMAP.run!(scanner)
```
```julia
#Display port id, state and service names
for host in scan.hosts
  for ports in host.ports
    for (port, extraport) in ports
      println(@sprintf("%s: %s %s", NMAP.id(port), NMAP.name(port), NMAP.state(port).state))
      #= Alternatively =#
      println("$(port.id): $(port.service.name) $(port.state.state)")
    end
  end
end
```
```julia-repl
80: http open
443: https closed
```
Scanners arguments can be defined as strings, NMAP.Option or both
```julia 
scanner = NMAP.Scanner("127.0.0.1", "-sV", NMAP.top_ports(100))
Cmd(scanner)
# `nmap 127.0.0.1 -sV --top-ports 100`
```
### Parse xml file as a Scan

```julia
scan = NMAP.Scan(read("path/to/output.xml"))
```
### Control scanner output
Documentation available under `docs/examples/Output.md`

---------------------------------------------

**Additional examples available** under `docs/examples`

## License
NMAP.jl is licensed under the [MIT License](LICENSE.txt)

## Options

Option documentation available under `docs/examples/Options.md`

## Internal structures

### Scan anatomy
```json
{
    "xml": "String",
    
    "args": "String",
    "scanner": "String",
    "startstr": "String",
    "version": "String",
    "xmloutputversion": "String",
    
    "start": "NMAP.Timestamp",
    "verbose": "NMAP.Verbose",
    "debugging": "NMAP.Debugging",
    "stats": "NMAP.RunStats",
    "scaninfo": "NMAP.ScanInfo",
    "hosts": "Array{NMAP.Host,1}",
    "targets": "Array{NMAP.Target,1}",
    "taskbegin": "Array{NMAP.Task,1}",
    "taskend": "Array{NMAP.Task,1}"
}
```
