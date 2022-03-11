module Marshalling

using JSON
using XMLDict

export Leaf, Marsh
export Parse
export fields, unmarshall

abstract type Marsh end
abstract type Leaf <: Marsh end

fields(::Type{T}) where T = ()

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
    # @show "unmarshal", T
    # println("####")
    # println(JSON.json(xml, 4))
    # println(JSON.json(Parse(T, xml)))
    # println("####")

    for (k, v) in Parse(T, xml)
        field = getfield(T, k)
        @show T, k
        println(field, JSON.json(xml, 4))
        # @show T,k,field
        # @show T, field, JSON.parse(JSON.json(xml))

        typemap  = Dict([name=>type for (name, type) in zip(fieldnames(T), T.types)])
        proptype = typemap[field]

        if field in fieldnames(T)
            if Marshalling.isleaf(k, v)
                if !(v isa proptype)
                    if (check = tryparse(proptype, v)) !== nothing
                        v = check
                    else
                        try
                            v = Base.convert(type, v)
                        catch;
                        end
                    end
                end
                Base.setproperty!(this, field, v)
            else
                @show field, typeof(v)
                println(proptype, " --> ", JSON.json(v, 4))
                if isempty(v)
                    Base.setproperty!(this, field, proptype())
                else
                    Base.setproperty!(this, field, Marshalling.unmarshall(proptype, v))
                end
            end
        end
    end
    return this
end
function unmarshall(::Type{Vector{T}}, xml::Vector) where T<:Marsh
    @show "vector vector"
    # @show "here", JSON.parse(JSON.json(xml))
    return [unmarshall(T, entry) for entry in xml]
end
function unmarshall(::Type{Vector{T}}, xml::XMLDict.XMLDictElement) where T<:Marsh
    @show "vector dictElement"
    return Vector{T}([unmarshall(T, xml)])
end

isleaf(value) = !(value isa XMLDict.XMLDictElement)
function isleaf(k::T, v) where T<:Union{Symbol, String}
    return k isa Symbol && isleaf(v)
end
isleaf(::Type{T}) where T<:Leaf  = true
isleaf(::Type{T}) where T<:Marsh = T <: Leaf

function Base.Dict(m::T) where T<:Marsh
    out = Dict()
    for (prop, type) in zip(fieldnames(T), T.types)
        value = Base.getproperty(m, prop)
        if type <: Vector{<:Marsh}
            value = Dict.(value)
        elseif type <: Marsh
            value = Dict(value)
        end
        out[string(prop)] = value
    end
    return out
end
JSON.json(m::T, args...; kwargs...) where T<:Marsh = JSON.json(Dict(m), args...; kwargs...)

end #end module
