module Marshalling

using JSON
using XMLDict

export Leaf, Marsh
export Parse
export fields, unmarshall

"""
    Marsh

XML nodes that either have children or whose associated Type is comprised of other `Marsh` types
"""
abstract type Marsh end

"""
    Leaf

A `XML node` with no children

When unmarshalling, either parsed to a Type or attributes are mapped to Type properties
"""
abstract type Leaf <: Marsh end

"""
    fields(::Type{T}) :: NamedTuple

Defines assocation between xml attrs and properties of T
"""
fields(::Type{T}) where T = ()

"""
    getfield(::Type{T}, k)

Obtain property `k` as defined under `fields(::T)`, or default to `k`
"""
function getfield(::Type{T}, k::Symbol) where T<:Marsh
    mappedfields = fields(T)
    return isempty(mappedfields) || !haskey(mappedfields, k) ? k : mappedfields[k]
end
getfield(::Type{T}, k::String) where T<:Marsh = getfield(T, Symbol(k))

function Parse(::Type{T}, xml) where T<:Union{Marsh, Vector{<:Marsh}} return xml end

unmarshall(::Type{T}, v) where T<:Any = v

unmarshall(::Type{I}, s::String) where I<:Int = parse(I, s)
unmarshall(::Type{V}, s::S) where {V<:Vector, S<:AbstractString} = [string(s)]
function unmarshall(::Type{T}, xml::XMLDict.XMLDictElement) where T<:Marsh
    this = T()

    for (k, v) in Parse(T, xml)
        field = getfield(T, k)
        typemap  = Dict([name=>type for (name, type) in zip(fieldnames(T), T.types)])
        proptype = typemap[field]

        if field in fieldnames(T)
            if isleaf(k, v)
                if !(v isa proptype)
                    # attempt to change `v` to the appropriate `type`
                    if proptype <: Number
                        if (check = tryparse(proptype, v)) !== nothing
                            v = check
                        end
                    else
                        try
                            v = unmarshall(proptype, v)
                        catch err
                            v = Base.convert(proptype, v)
                        end
                    end
                end
                Base.setproperty!(this, field, v)
            else
                if !isempty(v)
                #     Base.setproperty!(this, field, proptype())
                # else
                    Base.setproperty!(this, field, unmarshall(proptype, v))
                end
            end
        end
    end
    return this
end
function unmarshall(::Type{Vector{T}}, xml::Vector) where T<:Marsh
    return [unmarshall(T, entry) for entry in xml]
end
function unmarshall(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Marsh
    return Vector{T}([unmarshall(T, xml)])
end

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
            iter = collect(zip(keys(fields(T)), values(fields(T))))
            if (idx = findall(x->last(x) == prop, iter)) |> !isempty
                prop = first(first(iter[idx]))
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
