
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
