#================================
    Service
================================#
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

confidence(service::Service)  = service.confidence
fingerprint(service::Service) = service.servicefp
name(service::Service) = service.name
hostname(service::Service) = hostname(service.hostname)
product(service::Service)  = hostname.product

Base.string(service::Service) = name(service)

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

#=======================
    END Service
=======================#


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
