#========================
    NSE scripts
========================#
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
