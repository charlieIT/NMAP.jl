include("os.jl")
#=
[NMAP XML DTD](https://nmap.org/book/nmap-dtd.html)
=#
"""
    ScanInfo
"""
Base.@kwdef mutable struct ScanInfo <:Leaf
    numservices::Int    = 0
    protocol::String    = ""
    flags::String       = ""
    services::String    = ""
    type::String        = ""
end
StructTypes.names(::Type{ScanInfo}) = ((:flags, :scanflags),)

Base.@kwdef mutable struct Finished <:Leaf
    time::String        = ""
    timestr::String     = ""
    elapsed::String     = ""
    summary::String     = ""
    exit::String        = ""
    errormsg::String    = ""
end

Base.@kwdef mutable struct Hosts <:Leaf
    up::Int     = 0
    down::Int   = 0
    total::Int  = up + down
end

"""
    RunStats

Represents the runstats of a nmap scan
"""
Base.@kwdef mutable struct RunStats <:Leaf
    finished::Finished  = Finished()
    hosts::Hosts        = Hosts()
end

Base.@kwdef mutable struct Times <:Leaf
    srtt::String    = ""
    rtt::String     = ""
    to::String      = ""
end
StructTypes.names(::Type{Times}) = ((:rtt, :rttvar),)

"""
    Hop

Represents a hop in a traceroute
"""
Base.@kwdef mutable struct Hop <:Leaf
    ttl::Float64        = 0.0
	rtt::String         = ""
	ipaddr::String     = ""
	host::String        = ""
end

"""
    Trace

Representes the trace element in nmap scans
"""
Base.@kwdef mutable struct Trace <:Marsh
    proto::String       = ""
    port::Int           = 0
    hops::Vector{Hop}   = Vector{Hop}()
end
StructTypes.names(::Type{Trace}) = ((:hops, :hop),)

"""
    Reason

Reason why a port is closed or filtered

Available when `withReason` is used
"""
Base.@kwdef mutable struct Reason <:Marsh
    reason::String  = ""
    count::Int      = 0
    proto::String   = ""
    ports::String   = ""
end

"""
    ExtraPort

Info on closed and filtered ports
"""
Base.@kwdef mutable struct ExtraPort <:Marsh
    state::String           = ""
    count::Int              = 0
    reasons::Vector{Reason} = Vector{Reason}()
end
StructTypes.names(::Type{ExtraPort}) = ((:reasons, :extrareasons),)

"""
    Hostname

Host characterization
"""
Base.@kwdef mutable struct Hostname <:Leaf
    name::String    = ""
    type::String    = ""
end
name(host::Hostname) = host.name
Base.string(hname::Hostname) = name(hname)

# Tackle some inconsistency on how <hostnames> <hostname> </hostname> ... </hostnames> is provided
function StructTypes.construct(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Hostname
    xml = Dict(xml)
    if haskey(xml, "hostname") xml = xml["hostname"] end
    if !(xml isa Vector) xml = [xml] end
    return [StructTypes.construct(T, hname) for hname in xml]
end

"""
    Distance

Number of hops to an host
"""
Base.@kwdef mutable struct Distance <:Leaf
    value::String   = ""
end

"""
    Uptime

The amount of time the host has been up
"""
Base.@kwdef mutable struct Uptime <:Leaf
    seconds::Int     = 0
    lastboot::String = ""
end

#=
    Sequences
=#
abstract type AbstractSequence <: Marsh end

"""
    Sequence
"""
Base.@kwdef mutable struct Sequence <:Leaf
    class::String   = ""
    values::String  = ""
end

"""
    TCPSequence
"""
Base.@kwdef mutable struct TCPSequence <:Leaf
    index::String       = ""
    difficulty::String  = ""
    values::String      = ""
end
#= end Sequences =#

"""
    Address

The ip address and type (ipv4 or ipv6) or MAC Address
Vendor details may require nmap to be executed as a privileged user
"""
Base.@kwdef mutable struct Address <:Leaf
    addr::String        = ""
    addrtype::String    = ""
    vendor::String      = ""
end

"""
    HostStatus

An host's state, e.g. "up" with respective `reason`
"""
Base.@kwdef mutable struct HostStatus <:Leaf
    state::String       = ""
    reason::String      = ""
    reason_ttl::String  = ""
end
Base.string(status::HostStatus) = status.state

"""
    Smurf

Responses from smurf attacks
"""
Base.@kwdef mutable struct Smurf <:Marsh
    responses::String  = ""
end

#==
    NSE scripts
==#
"""
    Element

A script or table elemental block
"""
Base.@kwdef mutable struct Element <:Leaf
    key::String     = ""
    value::String   = ""
end
function StructTypes.construct(::Type{T}, value::AbstractString) where T<:Element
    return Element(value = string(value))
end
function StructTypes.construct(::Type{Vector{T}}, value::AbstractString) where T<:Element
    return Vector{T}([Element(value = string(value))])
end

"""
    Table

Set of Elements and subtables related to a script's execution

All fields can be empty
"""
Base.@kwdef mutable struct Table <:Marsh
   key::String               = ""
   tables::Vector{Table}     = Vector{Table}()
   elements::Vector{Element} = Vector{Element}()
end
StructTypes.names(::Type{Table}) = ((:elements, :elem), (:tables, :table))

"""
    Script
"""
Base.@kwdef mutable struct Script <:Marsh
    id::String                  = ""
    output::String              = ""
    elements::Vector{Element}   = Vector{Element}()
    tables::Vector{Table}       = Vector{Table}()
end
StructTypes.names(::Type{Script}) = ((:tables, :table), (:elements, :elem))
# //TODO Tackle some inconsistencies
function StructTypes.construct(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Script
    if haskey(xml, "script")
        xml = xml["script"]
    end
    if !(xml isa Vector) xml = [xml] end
    return Vector{T}([StructTypes.construct(Script, script) for script in xml])
end
#= end NSE scripts =#

"""
    Owner

Represents a port owner
"""
Base.@kwdef mutable struct Owner <:Leaf
    name::String      = ""
end
name(o::Owner) = o.name
Base.string(o::Owner) = name(o)

"""
    ServiceState

Information on a port's status, e.g. open, closed, reason, etc
"""
Base.@kwdef mutable struct ServiceState <:Leaf
    state::String        = ""
    reason::String       = ""
    reason_ip::String    = ""
    reason_ttl::String   = ""
end
state(ss::ServiceState) = ss.state
Base.string(ss::ServiceState) = state(ss)

"""
    Service

Information about services on open ports
"""
Base.@kwdef mutable struct Service <:Marsh
    devicetype::String      = ""
	extrainfo::String       = ""
	highversion::String     = ""
	hostname::String        = ""
	lowversion::String      = ""
	method::String          = ""
	name::String            = ""
	ostype::String          = ""
	product::String         = ""
	proto::String           = ""
	rcpum::String           = ""
	servicefp::String       = ""
	tunnel::String          = ""
	version::String         = ""
	confidence::Int         = 0
	cpe::Vector{String}     = Vector{String}()
end
StructTypes.names(::Type{Service}) = ((:confidence, :conf),)
name(service::Service) = service.name
Base.string(service::Service) = name(service)

#@enum PortState open closed filtered unfilterd Symbol("open|filtered") Symbol("closed|filtered")


"""
    Port

Details on a scanned port
"""
mutable struct Port <: Marsh
    id::Int64
    protocol::String
    owner::Owner
    state::ServiceState
    service::Service
    scripts::Vector{Script}

    function Port()
        return new(
            0, "", Owner(), ServiceState(), Service(), Vector()
        )
    end
end
StructTypes.names(::Type{Port}) = ((:id, :portid), (:state, :state), (:scripts, :script))
id(port::Port)       = port.id
name(port::Port)     = name(port.service)
owner(port::Port)    = port.owner
protocol(port::Port) = port.protocol
scripts(port::Port)  = port.scripts
service(port::Port)  = port.service
state(port::Port)    = port.state

"""
    Ports

Utility structure

Information on scanned ports (<ports> and <extraports>)
"""
Base.@kwdef mutable struct Ports <:Marsh
    ports::Vector{Port}             = Vector{Port}()
    extraports::Vector{ExtraPort}   = Vector{ExtraPort}()
end
StructTypes.names(::Type{Ports}) = ((:ports, :port),)

# Ease iteration over Ports
function Base.iterate(ps::Ports, state=1)
    if state + 1 > length(ps.ports)
        return nothing
    end
    extra = state+1 > length(ps.extraports) ? nothing : ps.extraports[state+1]
    return ([ps.ports[state+1], extra], state+1)
end

"""
    Verbose

Verbosity level
"""
Base.@kwdef mutable struct Verbose <:Leaf
    level::Int = 0
end

Base.@kwdef mutable struct Debugging <:Leaf
    level::Int = 0
end

level(x::T) where T<:Union{Debugging, Verbose} = x.level

"""
    Timestamp
"""
Base.@kwdef mutable struct Timestamp <:Leaf
    time::Int       = 0
    date::DateTime  = unix2datetime(time)
end
Timestamp(unix::Int)    = Timestamp(time = unix)
Timestamp(unix::String) = Timestamp(parse(Int, unix))
#Base.convert(::Type{Timestamp}, unix::Union{String, Int64}) = Timestamp(unix)
function StructTypes.construct(::Type{Timestamp}, unix::T) where T<:Union{String, Int}
    return Timestamp(unix)
end
time(ts::Timestamp) = ts.time
date(ts::Timestamp) = ts.date

Base.@kwdef mutable struct Task <:Leaf
    task::String        = ""
    time::Timestamp     = Timestamp()
    extrainfo::String   = ""
end

"""
    Target

How a target was specified when passed to nmap, its status and reasoning

Example xml
```xml
<target specification="domain.does.not.exist" status="skipped" reason="invalid"/>
```
"""
Base.@kwdef mutable struct Target <: Marsh
    specification::String   = ""
    status::String          = ""
    reason::String          = ""
end

"""
    Host

Representation of a scanned host

https://nmap.org/book/nmap-dtd.html
"""
Base.@kwdef mutable struct Host <: Marsh
    comment::String                 = ""
    distance::Distance              = Distance()
    endtime::Timestamp              = Timestamp()
    ipidsequence::Sequence          = Sequence()
    os::OS                          = OS()
    starttime::Timestamp            = Timestamp()
    status::HostStatus              = HostStatus()

    tcpsequence::TCPSequence        = TCPSequence()
    tcptssequence::Sequence         = Sequence()

    times::Times                    = Times()
    trace::Trace                    = Trace()
    uptime::Uptime                  = Uptime()

    addresses::Vector{Address}      = Vector{Address}()
    hostnames::Vector{Hostname}     = Vector{Hostname}()
    hostscripts::Vector{Script}     = Vector{Script}()
    ports::Vector{Ports}            = Vector{Ports}()
    smurfs::Vector{Smurf}           = Vector{Smurf}()
end
StructTypes.names(::Type{Host}) = (
    (:addresses,    :address),
    (:extraports,   :extraport),
    (:hostnames,    :hostname),
    (:ports,        :port),
    (:hostscripts,  :hostscript),
    (:smurfs,       :smurf))

hostnames(host::Host)   = host.hostnames
os(host::Host)          = host.os
ports(host::Host)       = host.ports

"""
    Scan

Nmap executed scan
"""
Base.@kwdef mutable struct Scan <:Marsh
    #= File =#
    xml::String
    #= end File =#

    args::String             = ""
    scanner::String          = ""
    startstr::String         = ""
    version::String          = ""
    xmloutputversion::String = ""

    start::Timestamp        = Timestamp()

    verbose::Verbose         = Verbose()
    debugging::Debugging     = Debugging()
    runstats::RunStats       = RunStats()
    scaninfo::ScanInfo       = ScanInfo()
    hosts::Vector{Host}      = Vector{Host}()
    targets::Vector{Target}  = Vector{Target}()
    # Tasks
    taskbegin::Vector{Task}  = Vector{Task}()
    taskend::Vector{Task}    = Vector{Task}()
end
StructTypes.names(::Type{Scan}) = ((:hosts, :host), (:runstats, :runstats))

"""
    Scan(xml::XMLDict.XMLDictElement) ::Scan

Build a `Scan` from an input `xml` document

For usage simplicity, this is implemented at constructor level

Examples
```julia
#= Import external scan results =#
scan = NMAP.Scan(read("myscan.xml"))
```
"""
function Scan(xml::XMLDict.XMLDictElement) ::Scan

    this = Scan(xml = XMLDict.dict_xml(XMLDict.xml_dict(xml))) # ~= initial xml string

    outputversion = get(xml, :xmloutputversion, "0.0.0")
    if !(outputversion in OUTPUT_VERSIONS)
        @warn "Detected potentially unsupported XML output version $(outputversion), parsing may fail or produce inaccurate results"
    end
    for (k,v) in xml
        field = Marshalling.getfield(Scan, k)
        typemap = Dict([name=>type for (name, type) in zip(fieldnames(Scan), Scan.types)])
        if field in fieldnames(Scan)
            Base.setproperty!(this, field, StructTypes.construct(typemap[field], v))
        end
    end
    return this
end

"""
    Scan(xml::String)

Dispatcher method to allow `scan = NMAP.Scan("<xml>....</xml>")`
"""
Scan(xml::String) = Scan(XMLDict.parse_xml(String(xml)))

"""
    Scan(data::Vector{UInt8})

Dispatcher method to allow `scan = NMAP.Scan(read("path/to/file.xml"))`
"""
Scan(data::Vector{UInt8}) = Scan(String(data))
