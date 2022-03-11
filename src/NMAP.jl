"""
NMAP library aims to provide idiomatic nmap bindings, in order to aid the creation of security audit tools using Julia
"""
module NMAP

    using EzXML
    using JSON
    using Lazy: Lazy, @forward
    using Revise
    using XMLDict

    include("marshalling.jl")
    using .Marshalling: Marshalling, fields, Marsh, Leaf, Parse, unmarshall
    include("os.jl")
    include("xml.jl")
    include("scan.jl")
    include("timing.jl")
#   include("methods.jl")

end
