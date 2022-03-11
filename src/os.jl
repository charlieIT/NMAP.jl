Base.@kwdef mutable struct PortUsed <:Leaf
    state::String   = ""
    proto::String   = ""
    id::Int         = 0
end
Marshalling.fields(::Type{PortUsed}) = (portid=:id,)

Base.@kwdef mutable struct OSFingerprint <:Leaf
    fingerprint::String = ""
end

Base.@kwdef mutable struct OSClass <:Marsh
    type::String            = ""
    vendor::String          = ""
    family::String          = ""
    gen::String             = ""
    accuracy::Int           = 0
    cpes::Vector{String}    = Vector{String}()
end
family(class::OSClass) = class.family
Marshalling.fields(::Type{OSClass}) = (
    cpe = :cpes,
    osfamily = :family,
    osgen = :gen
)

Base.@kwdef mutable struct OSMatch <:Marsh
    name::String                = ""
    accuracy::Int               = 0
    line::Int                   = 0
    classes::Vector{OSClass}    = Vector{OSClass}()
end
Marshalling.fields(::Type{OSMatch}) = (
    osclass = :classes,
)

Base.@kwdef mutable struct OS <:Marsh
    ports::Vector{PortUsed}              = Vector{PortUsed}()
    matches::Vector{OSMatch}             = Vector{OSMatch}()
    fingerprints::Vector{OSFingerprint}  = Vector{OSFingerprint}()
end
Marshalling.fields(::Type{OS}) = (
    portused = :ports,
    osmatch  = :matches,
    osfingerprint = :fingerprints
)
