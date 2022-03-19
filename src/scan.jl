
#======================================================

  [NMAP XML DTD](https://nmap.org/book/nmap-dtd.html)

=======================================================#

"""
    Timestamp
"""
Base.@kwdef mutable struct Timestamp <:Leaf
    time::Int       = 0
    date::DateTime  = unix2datetime(time)
end
Timestamp(unix::Int)    = Timestamp(time = unix)
Timestamp(unix::String) = Timestamp(parse(Int, unix))
function StructTypes.construct(::Type{Timestamp}, unix::T) where T<:Union{String, Int}
    return Timestamp(unix)
end
time(ts::Timestamp) = ts.time
date(ts::Timestamp) = ts.date

"""
    Task

Represents an nmap Task
"""
Base.@kwdef mutable struct Task <:Leaf
    task::String        = ""
    time::Timestamp     = Timestamp()
    extrainfo::String   = ""
end
time(task::Task) = task.time
date(task::Task) = time(task).date

include("xml/script.jl")
include("xml/os.jl")
include("xml/port.jl")
include("xml/ports.jl")
include("xml/host.jl")

"""
    Verbose

Verbosity level
Wraps the verbose xml element
"""
Base.@kwdef mutable struct Verbose <:Leaf
    level::Int = 0
end

"""
    Debugging

Wraps the debugging xml element
"""
Base.@kwdef mutable struct Debugging <:Leaf
    level::Int = 0
end
level(x::T) where T<:Union{Debugging, Verbose} = x.level

"""
    ScanInfo

Wraps the `scaninfo` xml element
"""
Base.@kwdef mutable struct ScanInfo <:Leaf
    numservices::Int    = 0
    protocol::String    = ""
    flags::String       = ""
    services::String    = ""
    type::String        = ""
end
StructTypes.names(::Type{ScanInfo}) = ((:flags, :scanflags),)

"""
    Finished

Wraps the `finished` xml element
"""
Base.@kwdef mutable struct Finished <:Leaf
    time::String        = ""
    timestr::String     = ""
    elapsed::String     = ""
    summary::String     = ""
    exit::String        = ""
    errormsg::String    = ""
end

"""
    Hosts

Wraps the `hosts` xml element
"""
Base.@kwdef mutable struct Hosts <:Leaf
    up::Int     = 0
    down::Int   = 0
    total::Int  = up + down
end

"""
    RunStats

Represents the runstats of a nmap scan
"""
Base.@kwdef mutable struct RunStats <:Leaf
    finished::Finished  = Finished()
    hosts::Hosts        = Hosts()
end

"""
    Target

How a target was specified when passed to nmap, its status and reasoning

Example xml
```xml
<target specification="domain.does.not.exist" status="skipped" reason="invalid"/>
```
"""
Base.@kwdef mutable struct Target <: Marsh
    specification::String   = ""
    status::String          = ""
    reason::String          = ""
end

"""
    Scan

Nmap executed scan
"""
Base.@kwdef mutable struct Scan <:Marsh
    #= File =#
    xml::String
    #= end File =#

    args::String             = ""
    scanner::String          = ""
    startstr::String         = ""
    version::String          = ""
    xmloutputversion::String = ""

    start::Timestamp         = Timestamp()
    verbose::Verbose         = Verbose()
    debugging::Debugging     = Debugging()
    runstats::RunStats       = RunStats()
    scaninfo::ScanInfo       = ScanInfo()
    hosts::Vector{Host}      = Vector{Host}()
    targets::Vector{Target}  = Vector{Target}()
    # Tasks
    taskbegin::Vector{Task}  = Vector{Task}()
    taskend::Vector{Task}    = Vector{Task}()
end
StructTypes.names(::Type{Scan}) = ((:hosts, :host), (:runstats, :runstats))

"""
    Scan(xmldict::XMLDict.XMLDictElement; rawxml=nothing) ::Scan

Build a `Scan` from an input `xml` document

For usage simplicity, this is implemented at constructor level

Examples
```julia
#= Import external scan results =#
scan = NMAP.Scan(read("myscan.xml"))
```
"""
function Scan(xmldict::XMLDict.XMLDictElement; xml::Union{Nothing, String}=nothing) ::Scan
    if isnothing(xml)
        # ~= initial xml string
        xml = XMLDict.dict_xml(XMLDict.xml_dict(xmldict))
    end
    this = Scan(xml = xml)

    outputversion = get(xmldict, :xmloutputversion, "0.0.0")
    if !(outputversion in OUTPUT_VERSIONS)
        @warn "Detected potentially unsupported XML output version $(outputversion), parsing may fail or produce inaccurate results"
    end
    for (k,v) in xmldict
        field = Marshalling.getfield(Scan, k)
        typemap = Dict([name=>type for (name, type) in zip(fieldnames(Scan), Scan.types)])
        if field in fieldnames(Scan)
            Base.setproperty!(this, field, StructTypes.construct(typemap[field], v))
        end
    end
    return this
end

"""
    Scan(xml::String) ::Scan


Build a `Scan` from an input `xml` string

Dispatcher method to allow `scan = NMAP.Scan("<xml>....</xml>")` and preserve the initial `xml` string
"""
function Scan(xml::String) ::Scan
    return Scan(XMLDict.parse_xml(xml), xml=xml)
end

"""
    Scan(data::Vector{UInt8}) ::Scan

Dispatcher method to allow `scan = NMAP.Scan(read("path/to/file.xml"))`
"""
Scan(data::Vector{UInt8}) = Scan(String(data))
