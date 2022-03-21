module Marshalling

using JSON
using StructTypes
using XMLDict

export Leaf, Marsh
export Parse
export fields, unmarshall

"""
    Marsh

XML nodes to be mapped to a structure

Usually types that either have children or whose associated Type is comprised of other `Marsh` types
"""
abstract type Marsh end

"""
    Leaf

A `XML node` with no children

When unmarshalling, either parsed to a Type or attributes are mapped to Type properties
"""
abstract type Leaf <: Marsh end

"""
    getfield(::Type{T}, k)

Wrapper around StructTypes.julianame(tuple::Tuple, serializationname::Symbol)

Obtain property `k` of `T`, as defined under `names(::T)`, or default to `k`
"""
function getfield(::Type{T}, k::Symbol) where T<:Marsh
    return StructTypes.julianame(StructTypes.names(T), k)
end
getfield(::Type{T}, k::String) where T<:Marsh = getfield(T, Symbol(k))

"""
    Parse(::Type{T}, xml) where T<:Union{Marsh, Vector{<:Marsh}}

Apply some parsing logic or transformation to input `xml` as a whole prior to creating an instanc of `T`
"""
function Parse(::Type{T}, xml) where T<:Union{Marsh, Vector{<:Marsh}} return xml end

# """
#     Parse(::Type{T}, prop::Val{Symbol}, v)

# Apply some transformation to value `v` of a specific `prop` of T
# """
# function Parse(::Type{T}, prop::V, v) where {T<:Union{Marsh, Vector{<:Marsh}} , V<:Val}
#     return v
# end

StructTypes.construct(::Type{T}, v) where T<:Any = v
StructTypes.construct(::Type{I}, s::String) where I<:Int = parse(I, s)
StructTypes.construct(::Type{V}, s::S) where {V<:Vector, S<:AbstractString} = [string(s)]

function StructTypes.construct(::Type{Vector{T}}, xml::Vector) where T<:Marsh
    return [StructTypes.construct(T, entry) for entry in xml]
end
function StructTypes.construct(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Marsh
    return Vector{T}([StructTypes.construct(T, xml)])
end

function StructTypes.construct(::Type{T}, xml::XMLDict.XMLDictElement) where T<:Marsh
    this = T()

    for (k, v) in Parse(T, xml)
        field    = getfield(T, k)
        typemap  = Dict([name=>type for (name, type) in zip(fieldnames(T), T.types)])

        if field in fieldnames(T)
            proptype = typemap[field]
            if isleaf(k, v)
                if !(v isa proptype)
                    # attempt to change `v` to the appropriate `type`
                    if proptype <: Number
                        if (check = tryparse(proptype, v)) !== nothing
                            v = check
                        end
                    else
                        try
                            v = StructTypes.construct(proptype, v)
                        catch err
                            v = Base.convert(proptype, v)
                        end
                    end
                end
                Base.setproperty!(this, field, v)
            else
                if !isempty(v)
                    Base.setproperty!(this, field, StructTypes.construct(proptype, v))
                end
            end
        else
            return StructTypes.construct(T, v)
        end
    end
    return this
end

"""
    unmarshall(::Type{T}, xml)

Dispatcher to prevent some inconvient overwrites when defining StructTypes.construct(T, input) over Base, Core or shared Types from other libs
"""
function unmarshall(::Type{T}, xml) where T return StructTypes.construct(T, xml) end

isleaf(value) = !(value isa XMLDict.XMLDictElement)
function isleaf(k::T, v) where T<:Union{Symbol, String}
    return k isa Symbol && isleaf(v)
end
isleaf(::Type{T}) where T<:Leaf  = true
isleaf(::Type{T}) where T<:Marsh = T <: Leaf

function Base.Dict(m::T; replace=false) where T<:Marsh
    out = Dict()
    for (prop, type) in zip(fieldnames(T), T.types)
        value = Base.getproperty(m, prop)
        if type <: Vector{<:Marsh}
            value = Dict.(value)
        elseif type <: Marsh
            value = Dict(value)
        end
        if replace
            names = StructTypes.names(T)
            if (idx = findall(x->first(x) == prop, names)) |> !isempty
                prop = last(first(names[idx]))
            end
        end
        out[string(prop)] = value
    end
    return out
end
function JSON.json(m::T, args...; replace=true, kwargs...) where T<:Marsh
    return JSON.json(Dict(m; replace=replace), args...; kwargs...)
end

end #end module
