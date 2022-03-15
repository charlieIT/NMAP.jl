Base.@kwdef mutable struct PortUsed <:Leaf
    id::Int         = 0
    proto::String   = ""
    state::String   = ""
end
Marshalling.fields(::Type{PortUsed}) = (portid=:id,)

Base.@kwdef mutable struct OSFingerprint <:Leaf
    fingerprint::String = ""
end
fingerprint(osf::OSFingerprint) = osf.fingerprint

Base.@kwdef mutable struct OSClass <:Marsh
    accuracy::Int           = 0
    family::String          = ""
    gen::String             = ""
    type::String            = ""
    vendor::String          = ""
    cpes::Vector{String}    = Vector{String}()
end
Marshalling.fields(::Type{OSClass}) = (cpe = :cpes, osfamily = :family, osgen = :gen)

accuracy(class::OSClass)    = class.accuracy
family(class::OSClass)      = class.family
gen(class::OSClass)         = class.gen
vendor(class::OSClass)      = class.vendor
type(class::OSClass)        = class.type


Base.@kwdef mutable struct OSMatch <:Marsh
    accuracy::Int               = 0
    line::Int                   = 0
    name::String                = ""
    classes::Vector{OSClass}    = Vector{OSClass}()
end
Marshalling.fields(::Type{OSMatch}) = (osclass = :classes,)

accuracy(match::OSMatch)    = match.accuracy
line(match::OSMatch)        = match.line
name(match::OSMatch)        = match.name

classes(match::OSMatch)     = match.classes
Base.string(match::OSMatch) = name(match)

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
