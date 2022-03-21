### Control scanner output - WIP

Still under active development and may be subject to change and improvements in the future

#### Redirect formatted output to a file
Use the argument `file` when invoking `run!`
```julia
 scanner = NMAP.Scanner(NMAP.targets("scanme.nmap.org"), NMAP.packet_trace())
 
 scan = NMAP.run!(scanner, file="output.xml")
 
 println(read("output.xml", String))
 ```
 ```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.70 scan initiated Tue Mar 15 19:47:03 2022 as: nmap -&#45;packet-trace -oX output.xml scanme.nmap.org -->
<nmaprun scanner="nmap" args="nmap -&#45;packet-trace -oX output.xml scanme.nmap.org" start="1647373623" startstr="Tue Mar 15 19:47:03 2022" version="7.70" xmloutputversion="1.04">
[...]
</nmaprun>
```
#### Redirect interactive output to an I/O
[_Interactive output is what Nmap prints to the stdout stream, which usually appears on the terminal window you executed Nmap from [...]_](https://nmap.org/book/output-formats-interactive.html)

This is essentially human readable information, not intended for automated/machine parsing and NMAP.jl will not keep it by default.
##### Redirect interactive output to a file
Define the `stdout` property of the `Scanner`
 ```julia
  scanner = NMAP.Scanner(NMAP.targets("scanme.nmap.org"), NMAP.packet_trace(), stdout="output.txt")
  scan = NMAP.run!(scanner)
  println(read("output.txt", String))
```
 ```text
Starting Nmap 7.70 ( https://nmap.org ) at 2022-03-15 19:39 UTC
SENT (0.0728s) ICMP [192.168.80.2 > 45.33.32.156 Echo request (type=8/code=0) id=8170 seq=0] IP [ttl=44 id=4437 iplen=28 ]
SENT (0.0728s) TCP 192.168.80.2:61637 > 45.33.32.156:443 S ttl=55 id=38043 iplen=44  seq=2695145412 win=1024 <mss 1460>
[...]
```
##### To custom I/O stream
 ```julia
  outbuffer = IOBuffer();
  scanner = NMAP.Scanner(NMAP.targets("scanme.nmap.org"), NMAP.packet_trace(), stdout=outbuffer)
  scan = NMAP.run!(scanner)
  println(String(take!(outbuffer)))
 ```

### Parse xml file as a Scan
```julia
 scan = NMAP.Scan(read("path/to/output.xml"))
```
### Obtain scan in different formats
Use the argument `sink` when invoking `run!` to define the scan format. Default behaviour is to return a `Scan instance`

#### Obtain output as `Dict` directly from execution
 ```julia
  #= Execute and obtain a Dict =#
  NMAP.run!(scanner, sink=Dict) # returns Dict 
```
#### Obtain Dict representation of a Scan
 ```julia
  #= Convert existing Scan to Dict =#
  scan = NMAP.run!(somescanner)
  Base.Dict(scan)
  #= Change keys to original nmap keys/element names =#
  Base.Dict(scan, replace=true)
```
#### Obtain as JSON
 ```julia
  #= Execute and obtain a JSON string =#
  NMAP.run!(scanner, sink=NMAP.Json) # Json, not JSON
  #= Convert existing Scan to JSON =#
  scan = NMAP.run!(somescanner)
  JSON.json(scan)
  #= Change keys to original nmap keys/element names =#
  JSON.json(scan, replace=true)
```
#### Obtain raw scan (`string` representation of the xml)
```julia
#= Execute and obtain output as a string =#
NMAP.run!(scanner, sink=String)
#= Obtain xml string from a scan instance =#
scan.xml
```
