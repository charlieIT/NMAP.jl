
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
Marshalling.fields(::Type{ScanInfo}) = (
    scanflags = :flags,
)

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
    RunStats <: Marsh

Part of `Scan`
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
Marshalling.fields(::Type{Times}) = (
    rttvar = :rtt,
)

Base.@kwdef mutable struct Hop <:Leaf
    ttl::Float64        = 0.0
	rtt::String         = ""
	ipaddrr::String     = ""
	host::String        = ""
end

Base.@kwdef mutable struct Trace <:Marsh
    proto::String       = ""
    port::Int           = 0
    hops::Vector{Hop}   = Vector{Hop}()
end
Marshalling.fields(::Type{Trace}) = (
    hops = :hop,
)

"""
    Reason

Reason why a port is closed or filtered

Available when `withReason` is used
"""
Base.@kwdef mutable struct Reason <:Marsh
    reason::String  = ""
    count::Int      = 0
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
Marshalling.fields(::Type{ExtraPort}) = (
    extrareasons = :reasons,
)

"""
    Hostname

Host characterization
"""
Base.@kwdef mutable struct Hostname <:Leaf
    name::String    = ""
    type::String    = ""
end

# Tacke some inconsistency on how <hostnames> <hostname> </hostname> ... </hostnames> is provided
function Marshalling.unmarshall(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Hostname
    xml = Dict(xml)
    if haskey(xml, "hostname") xml = xml["hostname"] end
    if !(xml isa Vector) xml = [xml] end
    return [Marshalling.unmarshall(T, hname) for hname in xml]
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

The ip address and type (ipv4 or ipv6)
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
Base.@kwdef mutable struct Element <:Marsh
    key::String     = ""
    value::String   = ""
end
function Marshalling.unmarshall(::Type{T}, value::AbstractString) where T<:Element
    return Element(value = string(value))
end
function Marshalling.unmarshall(::Type{Vector{T}}, value::AbstractString) where T<:Element
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
Marshalling.fields(::Type{Table}) = (
    elem    = :elements,
    table   = :tables
)

"""
    Script
"""
Base.@kwdef mutable struct Script <:Marsh
    id::String                  = ""
    output::String              = ""
    elements::Vector{Element}   = Vector{Element}()
    tables::Vector{Table}       = Vector{Table}()
end
Marshalling.fields(::Type{Script}) = (
    table = :tables,
    elem  = :elements
)
#= end NSE scripts =#

"""
    Owner

Represents a port owner
"""
Base.@kwdef mutable struct Owner <:Leaf
    name::String      = ""
end
Base.string(o::Owner) = o.name

"""
    ServiceState

Information on a port's status, e.g. open, closed, reason, etc
"""
Base.@kwdef mutable struct ServiceState <:Leaf
    state::String       = ""
    reason::String      = ""
    reason_ip::String    = ""
    reason_ttl::String   = ""
end

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
	serviceFP::String       = ""
	tunnel::String          = ""
	version::String         = ""
	confidence::Int         = 0
	cpe::Vector{String}     = Vector{String}()
end
Base.string(service::Service) = service.name
Marshalling.fields(::Type{Service}) = (
    conf = :confidence,
)

# Base.@kwdef mutable struct Port <:Marsh
#     id::Int64           = 0
#     protocol::String    = ""
#     owner::Owner        = Owner()
#     service::Service    = Service()
#     state::ServiceState = ServiceState()
#     scripts:Vector      = []
# end
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
Marshalling.fields(::Type{Port}) = (
    portid = :id,
    state  = :state,
    script = :scripts
)

"""
    Ports

Utility structure

Information on scanned ports (<ports> and <extraports>)
"""
Base.@kwdef mutable struct Ports <:Marsh
    ports::Vector{Port}             = Vector{Port}()
    extraports::Vector{ExtraPort}   = Vector{ExtraPort}()
end
Marshalling.fields(::Type{Ports}) = (
    port = :ports,
)

"""
    Verbose

Verbosity level
"""
Base.@kwdef mutable struct Verbose <: Leaf
    level::Int = 0
end

Base.@kwdef mutable struct Debugging <: Leaf
    level::Int = 0
end

"""
    Timestamp
"""
Base.@kwdef mutable struct Timestamp <: Leaf
    value::Int      = 0
    date::DateTime  = unix2datetime(value)
end
Timestamp(unix::Int)    = Timestamp(value = unix)
Timestamp(unix::String) = Timestamp(parse(Int, unix))
#Base.convert(::Type{Timestamp}, unix::Union{String, Int64}) = Timestamp(unix)
function Marshalling.unmarshall(::Type{Timestamp}, unix::T) where T<:Union{String, Int}
    return Timestamp(unix)
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
Marshalling.fields(::Type{Host}) = (
    address     = :addresses,
    extraport   = :extraports,
    hostname    = :hostnames,
    port        = :ports,
    hostscript  = :hostscripts,
    smurf       = :smurfs)
"""
    Scan

Nmap executed scan
"""
Base.@kwdef mutable struct Scan <:Marsh
    #= File =#
    rawxml::String
    xmldict::Dict
    #= end File =#
    args::String

    xmloutputversion::String = ""
    scanner::String          = ""
    startstr::String         = ""
    version::String          = ""

    start::Timestamp        = Timestamp()

    verbose::Verbose         = Verbose()
    debugging::Debugging     = Debugging()
    stats::RunStats          = RunStats()
    scaninfo::ScanInfo       = ScanInfo()
    hosts::Vector{Host}      = Vector{Host}()
    targets::Vector{Target}  = Vector{Target}()
end
Marshalling.fields(::Type{Scan}) = (
    host = :hosts,
    xmloutputversion = :xmloutputversion,
    runstats = :stats
)

function Base.getindex(r::Scan, i)
    return Base.getindex(r.xmldict, i)
end
