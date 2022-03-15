"""
NMAP library aims to provide idiomatic nmap bindings, in order to aid the creation of security audit tools using Julia
"""
module NMAP

    using Dates
    using EzXML
    using JSON
    using Lazy: Lazy, @forward
    using Printf
    using Revise
    using XMLDict

    include("unmarshalling.jl")
    using .Marshalling: Marshalling, Marsh, Leaf, fields, unmarshall
    include("os.jl")
    include("xml.jl")
    include("scan.jl")
    include("options.jl")
    include("timing.jl")
    #include("methods.jl")

end
