
#=
    Target and port specifiction
=#
"""
    ports(ports...) ::Option

Define ports the scanner should scan for each host
"""
function ports(ports...) :: Option
    portlist = join(string.(collect(ports)), ",")
    return Option(
        function(scan::Scanner)
            append!(scan.args, ["-p", portlist])
        end)
end

"""
    target(targets...) ::Option

Define scanner targets
"""
function targets(targets...) :: Option
    return Option(
        function(s::Scanner)
            push!(s.args, string.(targets)...)
        end)
end

"""
    random_targets(::Int) ::Option

Amount of targets to randomly choose from the available targets
"""
function random_targets(amount::Int64) ::Option
    return Option("-iR ", string(amount))
end

"""
    exclude(target::String, others...) ::Option

Set targets (hosts, networks, etc) to exclude from the scan
At least one target must be provided
"""
function exclude(target::String, others...) ::Option
    excluded = string(target, join(string.(collect(others)), ","))
    return Option(
        function(s::Scanner)
            push!(s.args, "--exclude")
            push!(s.args, excluded)
        end
    )
end

"""
    exclude_file(filepath::String)

Set input files that define target exclusions

See also: `exclude`
"""
function exclude_file(filepath::String) ::Option
    return Option(
        function(s::Scanner)
            push!(s.args, "--excludefile")
            push!(s.args, filepath)
        end
    )
end

#= end Target specification =#

function exclude_ports(ports...) ::Option

end

"""
    fastmode()

Faster scan that will scan fewer ports than the default scan
"""
function fastmode() return Option("-F") end

function consecutive_port_scan() return Option("-r") end

function top_ports(number::Int64) return Option("--top-ports", string(number)) end

function port_ratio(ratio::Float64)
    @assert ratio >= 1 and ratio >= 0 "port_ratio should be a value between 0 and 1"
    return Option("--port-ratio", @sprintf("%.1f", ratio))
end

#= end Port specification =#

#=
    Host Discovery
=#
"""
    listscan

-sL: List Scan - simply list targets to scan
"""
function listscan() return Option("-sL") end
"""
    pingscan

-sn: Ping Scan - disable port scan
"""
function pingscan() return Option("-sn") end
"""
    skip_discovery()

-Pn: Treat all hosts as online -- skip host discovery
"""
function skip_discovery() return Option("-Pn") end

"""
    syn_discovery(ports...) :: Option

Set discovery mode to use SYN packets

If no ports are provided, SYN discovery will be enabled for all ports

Alternatively, use `syn(ports...)`
"""
function syn_discovery(ports...) ::Option
    return Option(string("-PS", join(string.(collect(ports)), ",")))
end
syn(ports...) = syn_discovery()

"""
    ack_discovery(ports...)

Set discovery mode to use ACK packets

If no ports are provided, ACK discovery will be enabled for all ports

Alternatively, use `ack(ports...)`
"""
function ack_discovery(ports...) ::Option
    return Option(
        function(s::Scanner)
            push!(s.args, "-PA")
            push!(s.args, join(string.(collect(ports)), ","))
        end
    )
end
ack(ports...) = ack_discovery(ports...)

function udp_discovery(ports...)
    return Option(
        function(s::Scanner)
            push!(s.args, "-PU")
            push!(s.args, join(string.(collect(ports)), ","))
        end
    )
end
udp(ports...) = udp_discovery(ports...)

function sctp_discovery(ports...)
    return Option(
        function(s::Scanner)
            push!(s.args, "-PS")
            push!(s.args, join(string.(collect(ports)), ","))
        end
    )
end
sctp(ports...) = sctp_discovery(ports...)

"""
    discovery(modes...) ::Option

Utility option for grouping discovery mode definitions

Examples
```julia

scanner = Scanner(
    discovery(
        syn("22", "80"), # use syn packets for ports 22 and 80
        udp("9000"),     # use udp packets for port 9000
        ack()            # use ack packets in all ports
    )
)
```
"""
function discovery(modes...)
    @assert isempty(modes) || all(x->x isa Option, modes) "Provided arguments must be of type `Option`"
    return Option(
        function(scan::Scanner)
            [mode(scan) for mode in modes]
        end
    )
end

function icmp_echo_discovery()

end

function icmp_timestamp_discovery()

end

function icmp_netmask_discovery()

end

function ip_ping_discovery(protocols...)

end

function disabled_dns_resolution()
end

function forced_dns_resolution()
end

function dns_servers()
end

function system_dns()

end

"""
    traceroute()

Enable hop path tracing for each host
"""
function traceroute() return Option("--traceroute") end


#= end Host Discovery =#

#=
    Scan Techniques
=#

function syn_scan() return Option("-sS") end

function connect_scan() return Option("-sT") end

function ack_scan() return Option("-sA") end

function window_scan() return Option("-sW") end

function maimon_scan() return Option("-sM") end
"""
    updscan() ::Option

Enable scan technique to use UDP packets
"""
function udp_scan() return Option("-sU") end

"""
    tcp_null_scan() ::Option

Set scan technique to use TCP null packets - TCP flag header = 0

If a `RST` packet is received, port is considered closed.

If no response is received, the port is considered open|filtered
"""
function tcp_null_scan() return Option("-sN") end

function tcp_fin_scan() return Option("-sF") end

"""
    xmas_scan() ::Option

Set the scan technique to use TCP packets with FIN, PSH and URF flags set.

If a `RST` packet is received, port is considered closed.

If no response is received, the port is considered open|filtered
"""
function xmas_scan() return Option("-sX") end

function ip_protocol_scan() ::Option
    return Option("-sO")
end

"""
    ftp_bounce_scan(ftp_relay::String) ::Option

Enables FTP relay host scan technique
"""
function ftp_bounce_scan(ftp_relay::String) return Option("-b", ftp_relay) end

@enum TCPFlag begin
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
end

function tcp_scan_flags(flags...) ::Option
    @assert all(x->x isa Int64 || x isa TCPFlag) "TCP Flags must be of type Int or TCPFlag"
    value = sum([Int(flag) for flag in flags])
    # format as lowercase hexadecimal
    return Option("--scanflags", @sprintf("%x", value))
end

function idle_scan(zombie::String, port::Int64=0)
    return Option(
        function(s::Scanner)
            push!(s.args, "-sI")
            if port > 0
                # format as <string>:<int>
                push!(s.args, @sprintf("%s:%d", zombie, port))
            else
                push!(s.args, @sprintf("%s", zombie))
            end
        end
    )
end

function sctp_init_scan() return Option("-sY") end

function sctp_cookie_echo_scan() return Option("-sZ") end


#= end Scan Techniques =#

#= Service/Version detection =#

"""
    service_info() ::Option

Probe open ports to determine service/version info
"""
function service_info(options...) :::Option
    return Option(
        function(scanner::Scanner)
            push!(scanner.args, "-sV")
            [option(scanner) for option in options]
        end
    )
end

"""
    version_intensity(level) ::Option

Set the level of intensity with which nmap should probe the open ports to get version information.
Intensity should be a value between 0 (light) and 9 (try all probes).

Default value is 7
"""
function version_intensity(level::Int)
    @assert level >= 0 && level <= 9 "--version-intensity accepts values from 0 (light) to 9 (try all probes)"
    return Option("--version-intensity", level)
end
version_intensity() = version_intensity(7)
version_light()     = version_intensity(2)
version_all()       = version_intensity(9)

function version_trace()
    return Option("--version-trace")
end

#= end Service/Version detection =#

#= Script scan =#

function default_script()
    return Option("-sC")
end

function script(scripts...)
    list = join(string.(collect(scripts)), ",")
    return Option(
        function(scanner::Scanner)
            push!(scanner.args, @sprintf("--script=%s", list))
        end
    )
end

#= end Script scan =#

"""
    scandelay(delay::Int)

Sets the minimum time to wait between each probe sent to a host
"""
function scandelay(delay::Int) ::Option
end

#= IDS evasion, spoofind =#
function badsum() ::Option
   return Option("--badsum")
end
#= end IDS =#

#= OS Detection =#
"""
    os_detection(options...) :: Option

Example

```julia
    Scan(
        os_detection(
            osscan_guess(),
            osscan_limit()
        )
    )
```
"""
function os_detection(options...) :: Option
    @assert isempty(options) || all(x->x isa Option, options) "Provided arguments must be of type `Option`"
    return Option(
        function(scan::Scanner)
            push!(scan.args, "-O")
            for option in options
                option(scan)
            end
        end
    )
end

function osscan_guess() :: Option
    return Option((x)->push!(x.args, "--osscan-guess"))
end

function osscan_limit() :: Option
    return Option((x)->push!(x.args, "--osscan-limit"))
end

#= end OS Detection =#

#= Output options =#

abstract type OutputFormat end
abstract type GreppableFormat   <:OutputFormat end
abstract type kIddi3Format      <:OutputFormat end
abstract type NormalFormat      <:OutputFormat end
abstract type XMLFormat         <:OutputFormat end

Base.string(::Type{XMLFormat})          = "-oX"
Base.string(::Type{NormalFormat})       = "-oN"
Base.string(::Type{kIddi3Format})       = "-oS"
Base.string(::Type{GreppableFormat})    = "-oG"

function output(::Type{O}, file::String="-") where O<:OutputFormat
    return output(string(O), file)
end
function output(::Type{X}) where X<:XMLFormat
end
function output(format::String, file::String="-") ::Option
    return Option(
        function(s::Scanner)
            if !(format == string(XMLFormat))
                s.xml = false
            end
            push!(s.args, format, file)
        end
    )
end

function only_open() return Option("--open") end
function packet_trace() return Option("--packet-trace") end
function iflist()
    return Option(
        function(scanner::Scanner)
            scanner.debug = true
            push!(scanner.args, "--iflist")
        end
    )
end

function resume(logfile::String) ::Option
    return Option("--resume", logfile)
end

#= end Output options =#

#= Miscellaneous options =#

function ipv6_scanning()    return Option("-6") end
function aggressive_scan()  return Option("-A") end
function privileged()       return Option("--privileged") end
function unprivileged()     return Option("--unprivileged") end

#= end Miscellaneous options =#