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

"""
    Times

Wraps the `times` xml element
"""
Base.@kwdef mutable struct Times <:Leaf
    srtt::String    = ""
    rtt::String     = ""
    to::String      = ""
end
StructTypes.names(::Type{Times}) = ((:rtt, :rttvar),)

"""
    Smurf

Responses from smurf attacks
"""
Base.@kwdef mutable struct Smurf <:Marsh
    responses::String  = ""
end

"""
    Hop

Represents a hop in a traceroute
"""
Base.@kwdef mutable struct Hop <:Leaf
    ttl::Float64    = 0.0
	rtt::String     = ""
	ipaddr::String  = ""
	host::String    = ""
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
    Hostname

Host characterization
"""
Base.@kwdef mutable struct Hostname <:Leaf
    name::String    = ""
    type::String    = ""
end
name(host::Hostname) = host.name
type(host::Hostname) = host.type
Base.string(hname::Hostname) = name(hname)

# Tackle some inconsistency on how <hostnames> <hostname> </hostname> ... </hostnames> is provided
function StructTypes.construct(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Hostname
    xml = Dict(xml)
    if haskey(xml, "hostname") xml = xml["hostname"] end
    if !(xml isa Vector) xml = [xml] end
    return [StructTypes.construct(T, hname) for hname in xml]
end

#===================================
    Sequences
===================================#
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
#= END Sequences =#

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

address(host::Host)     = host.address
scripts(host::Host)     = host.hostscripts
hostnames(host::Host)   = host.hostnames
os(host::Host)          = host.os
ports(host::Host)       = host.ports
status(host::Host)      = host.status
