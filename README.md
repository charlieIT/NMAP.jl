## What is nmap 
**Nmap**, short for *Network Mapper*, is a [free and open source](https://nmap.org/npsl/) utility for network discovery and security auditing. Systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. [Read more](https://nmap.org/).

Nmap provides users with a powerful and flexible set of features for probing computer networks and perform [host discovery](https://nmap.org/book/man-host-discovery.html), service and [operating system detection](https://nmap.org/book/man-os-detection.html). Nmap's features are also extensible through scripts - [Nmap scripting engine](https://nmap.org/book/man-nse.html) - that provide more advanced features and automate a wider variety of network tasks, such as vulnerability detection or improved service detection. There is as collection of documented scripts available under [nsedoc](https://nmap.org/nsedoc/scripts/).
 
## Features

 - Parsing of XML output
	 - [XML](https://nmap.org/book/nmap-dtd.html) elements mapped to Julia structures
	 - Parsing externally generated xml files
-   `nmap`'s native options 
-  Enums and helpers for nmap commands
    - Time templates
    - OS families
    - Port states
-  Documentation and usage examples
	- Options documentation aligned with nmap's documentation
- Integration with CPE library 
 
 ## Example
```julia
using NMAP

scanner = NMAP.Scanner(
	NMAP.ports("22","80","443"),
	NMAP.targets("scanme.nmap.org"),
	NMAP.traceroute()
)
scan = NMAP.run(scanner)

#Display port id, state and service names
for host in scan.hosts
	for ports in host.ports
		for (port, extraport) in ports
			println("$(port.id): $(port.service.name) $(port.state.state)")
		end
	end
end
#=
80: http open
443: https closed
=#

#= 
Using NMAP helper methods
Acquire service names from the output
#=
names = NMAP.name.(NMAP.service.(NMAP.port.(scan.hosts)))
# [["ssh", "http", "https"]]
reduce(vcat, names)
# ["ssh", "http", "https"]
```

### Control scanner output
**Redirect interactive output to a file**
 ```julia
  scanner = NMAP.Scanner(NMAP.targets("scanme.nmap.org"), NMAP.packet_trace(), stdout="output.txt")
  scan = NMAP.run(scanner)
  println(read("output.txt", String))
```
 ```text
Starting Nmap 7.70 ( https://nmap.org ) at 2022-03-15 19:39 UTC
SENT (0.0728s) ICMP [192.168.80.2 > 45.33.32.156 Echo request (type=8/code=0) id=8170 seq=0] IP [ttl=44 id=4437 iplen=28 ]
SENT (0.0728s) TCP 192.168.80.2:61637 > 45.33.32.156:443 S ttl=55 id=38043 iplen=44  seq=2695145412 win=1024 <mss 1460>
[...]
```
 
```julia
 NMAP.name(scan.hosts)
# > ["scanme.nmap.org", "scanme.nmap.org"]
```
**Redirect formatted output to a file** 
 ```julia
  scan = NMAP.run(scanner, file="output.xml")
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
## Options
[Nmap options summary](https://nmap.org/book/man-briefoptions.html)
[Nmap usage](https://svn.nmap.org/nmap/docs/nmap.usage.txt)

#### TARGET SPECIFICATION
 ```julia
  targets(targets...) # pass hostnames, IP addresses, networks, etc.
  #= Examples: scanme.nmap.org, domain.com/24, 192.168.0.1; 10.0.0-255.1-254 =#
  targets("scanme.nmap.org", "192.168.80.0-12")
```
 ```julia
  random_targets(amount::Int) # -iR <amount> - Choose random targets
```
 ```julia
  exclude(target::String, others...) # --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
```
 ```julia
  exclude_file(filepath::String) # --excludefile <exclude_file>: Exclude list from file
```
  -iL <inputfilename>: Input from list of hosts/networks
##### HOST DISCOVERY
  
 ```julia 
  listscan() # -sL: List Scan - simply list targets to scan
  ```
  
 ```julia 
  pingscan() # -sn: Ping Scan - disable port scan
  ```
  
```julia 
 skiphostdiscovery() # -Pn: Treat all hosts as online -- skip host discovery
  ```

```julia 
 syn_discovery(ports...) # -PS[portlist]: TCP SYN discovery to given ports
 syn(ports...)
 ```
```julia 
 ack_discovery(ports...) # -PA[portlist]: TCP ACK discovery to given ports
 ack(ports...)
 ```
```julia 
 udp_discovery(ports...) # -PU[portlist]: UDP discovery to given ports
 udp(ports...)
 ```
```julia 
 sctp_discovery(ports...) # -PS[portlist]: SCTP discovery to given ports
 sctp(ports...)
 ```
```julia
 icmp_echo_discovery() 	    # -PE: ICMP echo request discovery probes
 icmp_timestamp_discovery() # -PP: ICMP timestamp request discovery probes
 icmp_netmask_discovery()   # -PM: ICMP netmask request discovery probes
 ```
 
 ```julia
  ip_ping_discovery(protocols...) # -PO[protocol list]: IP Protocol Ping
```
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
 ```julia
  traceroute() # --traceroute: Trace hop path to each host
```
##### SCAN TECHNIQUES
```julia
 syn_scan()			# -sS: TCP SYN scan
 ack_scan()			# -sA: TCP ACK scan
 connect_scan()		# -sT: TCP Connect() scan
 window_scan()		# -sW: TCP Window scan
 maimon_scan()		# -sM: TCP Maimon scan
 ```
 ```julia
  upd_scan() # -sU: UDP Scan
```
 ```julia
  tcp_null_scan() # -sN: TCP Null scan
  tcp_fin_scan()  # -sF: TCP FIN scan
  xmas_scan()     # -sX: Xmas scan
```
 ```julia
  tcp_scan_flags(flags...) # --scanflags <flags>: Customize TCP scan flags
  Enum NMAP.TCPFlag:
  NULL = 0
  FIN  = 1
  SYN  = 2
  RST  = 4
  PSH  = 8
  ACK  = 16
  URG  = 32
  ECE  = 64
  CWR  = 128
  NS   = 256
```
```julia
 idle_scan(zombie::String, port::Int64=0) # -sI <zombie host[:probeport]>: Idle scan
 ```
```julia
 sctp_init_scan() 		  # -sY: SCTP INIT scan
 sctp_cookie_echo_scan() # -sZ: SCTP COOKIE-ECHO scan
  ```
 ```julia
  ip_protocol_scan() # -sO: IP protocol scan
```
 ```julia
  ftp_bounce_scan(ftp_relay::String) # -b <FTP relay host>: FTP bounce scan
```
##### PORT SPECIFICATION AND SCAN ORDER
 ```julia
  ports(ports...) # -p <port ranges>: Only scan specified ports
```
 ```julia
  exclude_ports(ports...) # --exclude-ports <port ranges>: Exclude the specified ports from scanning
```
 ```julia
  fastmode() # -F: Fast mode - Scan fewer ports than the default scan
```
 ```julia
  consecutive_port_scan() # -r: Scan ports consecutively, don't randomize
```
 ```julia
  top_ports(number::Int) # --top-ports <number>: Scan <number> most common ports
```
 ```julia
  port_ratio(ratio::Float64) # --port-ratio <ratio>: Scan ports more common than <ratio>
```
##### SERVICE/VERSION DETECTION
 ```julia
  service_info() # -sV: Probe open ports to determine service/version info
  ```
```julia
  version_intensity(level::Int) # --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  version_light() # --version-light: Limit to most likely probes (intensity 2)
  version_all()   # --version-all: Try every single probe (intensity 9)
  version_trace() # --version-trace: Show detailed version scan activity (for debugging)
  ```
  ```julia
   service_info() # `-sV`
   service_info(version_all()) # `-sV --version-all`
  ```
##### SCRIPT SCAN
 ```julia
  default_script() # -sC: equivalent to --script=default
```
 ```julia
  script(scripts...) # --script=<Lua scripts>: <Lua scripts> is a comma separated list of directories, script-files or script-categories
```
  
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
  
##### OS DETECTION
```julia
 os_detection(os_options...) # -O: Enable OS detection
 osscan_limit() # --osscan-limit: Limit OS detection to promising targets
 osscan_guess() # --osscan-guess: Guess OS more aggressively
 #= Example =#
 os_detection(
	 osscan_limit(),
	 osscan_guess()) # `-O --osscan-limit --osscan-guess`
```
##### TIMING AND PERFORMANCE
```julia
 timingtemplate(timing) # -T<0-5>: Set timing template (higher is faster)
 Enum NMAP.Timing:
	paranoid 	= 0
	sneaky 		= 1
	polite 		= 2
	normal 		= 3
	aggressive 	= 4
	insane 		= 5
 #= Examples =#
 timingtemplate(NMAP.paranoid) 	# `-T0`
 timingtemplate(NMAP.insacen)  	# `-T5`
 timingtemplate(2)				# `-T2`
 timingtemplate(6)				# ERROR: AssertionError: Timing template values range from 0 to 5
  ```
  **Note**
  Options which take `<time>` are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  
--min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
##### FIREWALL/IDS EVASION AND SPOOFING
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  ```julia
   badsum() # --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
   ``` 
##### OUTPUT
```julia
 output(format::String, file::String="-") # -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
 #= Alternatively =#
 output(::Type{<:NMAP.OutputFormat}, file::String="-")
 output(NMAP.XMLFormat) #format as XML and redirect to stdout
 output(NMAP.NormalFormat, 	  "someFile.out") #redirect to file
 output(NMAP.kIddi3Format, 	  "example.kiddie")
 output(NMAP.GreppableFormat, "output.txt")
```

  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
 ```julia
  only_open() # --open: Only show open (or possibly open) ports
  ```
 ```julia
  packet_trace() # --packet-trace: Show all packets sent and received
  ```
**Note:**  `--iflist`will place the `Scanner` in debug mode, and the `Scan` object will not be automatically generated after scan completion.
 ```julia
  iflist() # --iflist: Print host interfaces and routes (for debugging)
  ```
  --append-output: Append to rather than clobber specified output files
 ```julia
  resume(logfile::String) # --resume <filename>: Resume an aborted scan
  ```
  --noninteractive: Disable runtime interactions via keyboard
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
##### MISC
```julia
 ipv6_scanning() # -6: Enable IPv6 scanning
  ```
```julia
 aggressive_scan() # -A: Enable OS detection, version detection, script scanning, and traceroute
  ```
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
 ```julia
  privileged() # --privileged: Assume that the user is fully privileged
  ```
 ```julia
  unprivileged() # --unprivileged: Assume the user lacks raw socket privileges
  ```