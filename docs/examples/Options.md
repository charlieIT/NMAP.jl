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
```julia
input_file(filepath::String) # -iL <inputfilename>: Input from list of hosts/networks
```
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
icmp_echo_discovery() # -PE: ICMP echo request discovery probes
icmp_timestamp_discovery() # -PP: ICMP timestamp request discovery probes
icmp_netmask_discovery() # -PM: ICMP netmask request discovery probes
```
```julia
ip_ping_discovery(protocols...) # -PO[protocol list]: IP Protocol Ping
```
###### WIP

-n/-R: Never do DNS resolution/Always resolve [default: sometimes]

--dns-servers <serv1[,serv2],...>: Specify custom DNS servers

--system-dns: Use OS's DNS resolver

```julia
traceroute() # --traceroute: Trace hop path to each host
```
##### SCAN TECHNIQUES
```julia
syn_scan() # -sS: TCP SYN scan
ack_scan() # -sA: TCP ACK scan
connect_scan() # -sT: TCP Connect() scan
window_scan() # -sW: TCP Window scan
maimon_scan() # -sM: TCP Maimon scan
```
```julia
upd_scan() # -sU: UDP Scan
```
```julia
tcp_null_scan() # -sN: TCP Null scan
tcp_fin_scan() # -sF: TCP FIN scan
xmas_scan() # -sX: Xmas scan
```
```julia
tcp_scan_flags(flags...) # --scanflags <flags>: Customize TCP scan flags

Enum NMAP.TCPFlag:
 NULL = 0
 FIN = 1
 SYN = 2
 RST = 4
 PSH = 8
 ACK = 16
 URG = 32
 ECE = 64
 CWR = 128
 NS = 256
```
```julia
idle_scan(zombie::String, port::Int64=0) # -sI <zombie host[:probeport]>: Idle scan
```
```julia
sctp_init_scan() # -sY: SCTP INIT scan
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
version_all() # --version-all: Try every single probe (intensity 9)
version_trace() # --version-trace: Show detailed version scan activity (for debugging)
```
```julia
service_info(version_all()) # `-sV --version-all`
```

##### SCRIPT SCAN
```julia
default_script() # -sC: equivalent to --script=default
```
```julia
script(scripts...) # --script=<Lua scripts>: <Lua scripts> is a comma separated list of directories, script-files or script-categories

script_args(args...; kwargs...) # --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts

#= Examples =#
script("default") # --script=default
script_args("key.property"=>value, "script.showall", user="foo")
```
###### WIP

--script-args-file=filename: provide NSE script args in a file

--script-trace: Show all data sent and received

--script-updatedb: Update the script database.

--script-help=<Lua  scripts>: Show help about scripts.

##### OS DETECTION

```julia
os_detection(os_options...) # -O: Enable OS detection
osscan_limit() # --osscan-limit: Limit OS detection to promising targets
osscan_guess() # --osscan-guess: Guess OS more aggressively

#= Example =#
os_detection(osscan_limit(),osscan_guess()) # `-O --osscan-limit --osscan-guess`
```
##### TIMING AND PERFORMANCE

```julia
timingtemplate(timing) # -T<0-5>: Set timing template (higher is faster)

Enum NMAP.Timing:
 paranoid = 0
 sneaky = 1
 polite = 2
 normal = 3
 aggressive = 4
 insane = 5

#= Examples =#
timingtemplate(NMAP.paranoid) # `-T0`
timingtemplate(NMAP.insacen) # `-T5`
timingtemplate(2) # `-T2`
timingtemplate(6) # ERROR: AssertionError: Timing template values range from 0 to 5
```
**Note**
Options which take `<time>` are in seconds, or append 'ms' (milliseconds), 's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).

##### Wip

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
```julia
decoy(decoys...) # -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys

spoof_source(ip::String) # -S <IP_Address>: Spoof source address

spoof_mac(mac::String) # --spoof-mac <mac  address/prefix/vendor  name>: Spoof your MAC address

interface(interface::String) # -e <iface>: Use specified interface

badsum() # --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
```
##### Wip

-f; --mtu <val>: fragment packets (optionally w/given MTU)

-g/--source-port <portnum>: Use given port number

--proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies

--data <hex  string>: Append a custom payload to sent packets

--data-string <string>: Append a custom ASCII string to sent packets

--data-length <num>: Append random data to sent packets

--ip-options <options>: Send packets with specified ip options

--ttl <val>: Set IP time-to-live field

##### OUTPUT

```julia
output(format::String, file::String="-") # -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.

#= Alternatively =#
output(::Type{<:NMAP.OutputFormat}, file::String="-")

output(NMAP.XMLFormat) #format as XML and redirect to stdout: "-"
output(NMAP.NormalFormat, "normal.text") #redirect to file
output(NMAP.kIddi3Format, "example.kiddie")
output(NMAP.GreppableFormat, "greppable.txt")
```
```julia
only_open() # --open: Only show open (or possibly open) ports
```
```julia
packet_trace() # --packet-trace: Show all packets sent and received
```

**Note:**  `--iflist` will place the `Scanner` in debug mode, and a `Scan` object will not be automatically generated after scan completion.

```julia
iflist() # --iflist: Print host interfaces and routes (for debugging)
```
##### Wip

-oA <basename>: Output in the three major formats at once

-v: Increase verbosity level (use -vv or more for greater effect)

-d: Increase debugging level (use -dd or more for greater effect)

--reason: Display the reason a port is in a particular state

--resume <filename>: Resume an aborted scan

##### Wip

--append-output: Append to rather than clobber specified output files

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
```julia
privileged() # --privileged: Assume that the user is fully privileged
```
```julia
unprivileged() # --unprivileged: Assume the user lacks raw socket privileges
```
--datadir <dirname>: Specify custom Nmap data file location

--send-eth/--send-ip: Send using raw ethernet frames or IP packets