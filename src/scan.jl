"""
    Scan

Examples
```julia
NMAP.Scanner(
    NMAP.ports("80"),
    NMAP.targets("127.0.0.1"),
    NMAP.timingtemplate(NMAP.paranoid)
)

NMAP.Scanner(
    NMAP.ports("80"),
    NMAP.targets("127.0.0.1"),
    NMAP.timingtemplate(NMAP.paranoid),
    NMAP.osdetection(
        NMAP.osscan_guess()
    )
)

NMAP.Scanner(
    NMAP.fastmode(),
    "-sV",
    NMAP.targets("127.0.0.1"),
)

NMAP.Scanner("-p1-80", "-sV", "127.0.01")
```
"""
Base.@kwdef mutable struct Scanner
    cmd::Cmd                = Cmd(``)
    args::Vector{String}    = Vector{String}()
    # port::Function          =
    # host::Function

    binpath::String         = "nmap"
    stderr                  = nothing
    stdout                  = nothing
    output::Vector{UInt8}   = Vector{UInt8}()
end

function Base.push!(scan::Scanner, arg)
    if arg isa Vector
        append!(scan.args, arg)
    else
        push!(scan.args, arg)
    end
end

function Scanner(options...;
    args::Vector{String} = Vector{String}(),
    binpath::String      = "nmap",
    kwargs...)

    scan = Scanner(args=args, binpath=binpath)
    for option in options
        if option isa Function || option isa Option
            option(scan)
        elseif option isa String
            push!(scan.args, option)
        elseif option isa Vector
            append!(scan.args, option)
        end
    end

    # Enable XML Output
    push!(scan.args, "-oX")
    # Write output to stdout
    push!(scan.args, "-")

    scan.cmd = Cmd([scan.binpath, scan.args...])

    return scan
end

"""
    Option
"""
mutable struct Option
    fn::Function
end
function(option::Option)(scan::Scanner)
    return option.fn(scan)
end

#=
Options implementation
=#
function ports(ports...) :: Option
    portlist = join(string.(collect(ports)), ",")
    return Option(
        function(scan::Scanner)
            append!(scan.args, ["-p", portlist])
        end
    )
end

function targets(targets...) :: Option
    return Option(
        function(s::Scanner)
            push!(s.args, targets...)
        end
    )
end

#=
    Host Discovery
=#
"""
    listscan

-sL: List Scan - simply list targets to scan
"""
function listscan() return "-sL" end
"""
    pingscan

-sn: Ping Scan - disable port scan
"""
function pingscan() return "-sn" end
"""
    skiphostdiscovery()

-Pn: Treat all hosts as online -- skip host discovery
"""
function skiphostdiscovery() return "-Pn" end

#= end Host Discovery =#

#=
    Scan Techniques
=#
"""
    updscan()

-sU: UDP Scan
"""
function udpscan() return "-sU" end
#= end Scan Techniques =#

"""
    fastmode()
"""
function fastmode() return "-F" end

"""
    scandelay(delay)
"""
function scandelay(delay) ::Option

end

function idlescan()

end

function ipprotocolscan()
    return Option((x)->push!(x, "-sO"))
end

#= IDS evasion, spoofind =#
function withBadSum()
    return "--badsum"
end
#= end IDS =#

#= OS Detection =#
"""
    osdetection(options...) :: Option

Example

```julia
    Scan(
        osdetection(
            osscan_guess(),
            osscan_limit()
        )
    )
```
"""
function osdetection(options...) :: Option
    @assert isempty(options) || all(x->x isa Option, options) "Provided arguments must be of type `Option`"
    return Option(
        function(scan::Scan)
            push!(scan.args, "-O")
            for option in options
                option(scan)
            end
        end
    )
end

function osscan_guess() :: Option
    return Option((x)->push!(x.args, "--osscan-guess"))
end

function osscan_limit() :: Option
    return Option((x)->push!(x.args, "--osscan-limit"))
end

#= end OS Detection =#

"""
    Run(scan::Scanner)
"""
function Run(scanner::Scanner) :: Scan
    raw = read(scanner.cmd, String)
    scanner.output = Vector{UInt8}(raw)
    return Marshalling.unmarshall(Scan, scanner)
end

using Serialization
function Marshalling.unmarshall(::Type{Scan}, scanner::Scanner)
    xmldict = XMLDict.parse_xml(String(scanner.output))

    this = Scan(
        rawxml  = String(scanner.output),
        xmldict = xmldict,
        args    = string(scanner.cmd)
    )
    # serialize("scan.xml", JSON.parse(JSON.json(xmldict)))
    # open("scan.json", "w") do io
    #     write(io, JSON.json(xmldict, 4))
    # end

    iter = deepcopy(xmldict)
    for (k,v) in iter
        field = Marshalling.getfield(Scan, k)
        typemap = Dict([name=>type for (name, type) in zip(fieldnames(Scan), Scan.types)])
        if field in fieldnames(Scan)
            Base.setproperty!(this, field, Marshalling.unmarshall(typemap[field], v))
        end
    end
    return this
end
