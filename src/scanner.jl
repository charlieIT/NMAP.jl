const OUTPUT_VERSIONS = ["1.04", "1.05"]

"""
# Scanner

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
    NMAP.os_detection(
        NMAP.osscan_guess()
    )
)

# Mixed option definition
NMAP.Scanner(
    NMAP.fastmode(),
    "-sV",
    NMAP.targets("127.0.0.1"),
)

# Options as strings
NMAP.Scanner("-p1-80", "-sV", "127.0.01")
```
"""
mutable struct Scanner
    cmd::Cmd
    args::Vector{String}

    binpath::String
    stderr
    stdout

    debug::Bool # When true,  will not attempt to generate Scan after completion
    xml::Bool   # When false, will not attempt to generate Scan after completion

    # create kwarg constructor to prevent some constructor and dispatch issues that appeared when using Base.@kwdef
    function Scanner(;
            cmd     = Cmd(``),
            args    = Vector{String}(),
            binpath = "nmap",
            stderr  = Base.stderr,
            stdout  = Base.stdout,
            debug   = false,
            xml     = true
        )
        return new(cmd, args, binpath, stderr, stdout, debug, xml)
    end
end

Base.push!(scanner::Scanner,    arg::String) = Base.push!(scanner.args, arg)
Base.push!(scanner::Scanner,    arg)         = Base.push!(scanner.args, string(arg))
Base.append!(scanner::Scanner,  args::Vector{String}) = append!(scanner.args, args)
Base.push!(scanner::Scanner,    args::Vector{String}) = append!(scanner, args)

function Base.Cmd(scanner::Scanner) ::Cmd
    return Cmd([scanner.binpath, scanner.args...])
end

"""
    function Scanner(options....; binpath::String = "nmap", kwargs...) ::Scanner

Build a Scanner from provided `options`

Input `options` can be strings, functions, Option objects or a mix of both

Examples

```julia
NMAP.Scanner(
    NMAP.ports("80"),
    NMAP.targets("127.0.0.1"),
    NMAP.timingtemplate(NMAP.paranoid))

NMAP.Scanner("-p1-80", "-sV", "127.0.01")

NMAP.Scanner(
    NMAP.fastmode(),
    "-sV",
    NMAP.targets("127.0.0.1"))
```
"""
function Scanner(options...;
    args::Vector{String} = Vector{String}(),
    binpath::String      = "nmap",
    stdout               = Base.stdout,
    stderr               = Base.stderr,
    debug::Bool          = false,
    kwargs...)

    this = Scanner(; args=args, binpath=binpath, stdout=stdout, stderr=stderr, debug=debug)

    for option in options
        if option isa Function || option isa Option
            option(this)
        elseif option isa String
            push!(this.args, option)
        elseif option isa Vector
            append!(this.args, option)
        end
    end
    this.cmd = Cmd(this)

    return this
end

"""
    Option

Options are used to group scanner options.

An Option will apply or remove options from scanner arguments. For some options, it can/will also mutate other scanner properties.

## Examples

### Defining an Option
```julia
opt = Option(function(scanner::Scanner) push!(scanner.args, "-someOpt") end)
```
### Using Option
```julia
opt = Option("-someOpt")

opts = Option("-someOpt", "someValue", anotherValue)

append!(scanner, [opt, opts])
```
"""
mutable struct Option
    fn::Function
end
function Option(option::String)
    return Option(
        function(scan::Scanner)
            push!(scan.args, option)
        end)
end
function Option(options...)
    return Option(
        function(scan::Scanner)
            [push!(scan, option) for option in options]
        end
    )
end

"""
    Apply `option` to `scanner`

Invokes `option.fn(scanner)`
"""
function(option::Option)(scanner::Scanner)
    return option.fn(scanner)
end

"""
    Apply `option` to `scanner`

Invokes `option(scanner)`
"""
function (scanner::Scanner)(option::Option)
    return option(scanner)
end

Base.push!(scanner::Scanner,    option::Option)          = option(scanner)
Base.append!(scanner::Scanner,  options::Vector{Option}) = [x(scanner) for x in options]
Base.push!(scanner::Scanner,    options::Vector{Option}) = append!(scanner, options)

"""
    forcexml(out::String="-") :: Option

Enable XML output in stdout
"""
function _forcexml(out::String = "-") ::Option
    return Option(
        function(scanner::Scanner)
            # Enable XML Output
            push!(scanner.args, "-oX")
            # Write output to output stream
            push!(scanner.args, out)
        end)
end

# Utility Type, as JSON is a Module, not a Type
abstract type Json end
const Sinks = Union{Scan, Dict, Json, String}

Marshalling.unmarshall(::Type{String}, xml::XMLDict.XMLDictElement; kwargs...) = String(XMLDict.dict_xml(xml))
Marshalling.unmarshall(::Type{Dict},   xml::XMLDict.XMLDictElement; kwargs...) = XMLDict.xml_dict(xml)
Marshalling.unmarshall(::Type{Json},   xml::XMLDict.XMLDictElement; kwargs...) = JSON.json(Marshalling.unmarshall(Dict, xml))
Marshalling.unmarshall(::Type{Scan},   xml::XMLDict.XMLDictElement; kwargs...) = Scan(xml)

Marshalling.unmarshall(::Type{String}, xml::String; kwargs...) = xml
Marshalling.unmarshall(::Type{Dict},   xml::String; kwargs...) = Marshalling.unmarshall(Dict, XMLDict.parse_xml(xml))
Marshalling.unmarshall(::Type{Json},   xml::String; kwargs...) = JSON.json(Marshalling.unmarshall(Dict, xml))
Marshalling.unmarshall(::Type{Scan},   xml::String; kwargs...) = Scan(xml)

"""
    run!(scan::Scanner)

run! the `scanner` synchronously and return scan results

Invoking `run!` will mutate the `scanner`

Default behaviour is to return a `Scan type`. This can be configured via `sink` kwarg

WIP: To redirect formatted output to both an output stream and Base.stdout, set `interactive` to false
"""
function run!(
        scanner::Scanner;
        autoremove::Bool             = true,
        interactive::Bool            = true,
        file::Union{Nothing, String} = nothing,
        replace::Bool                = false,
        sink::Type{S}                = Scan) where S<:Sinks

    if scanner.debug || !scanner.xml
        @warn "Scanning in debug mode, scan outputs will not be automatically parsed to a Scan"
    end

    if scanner.xml
        if !interactive
            # deactive interactive output and write results to standard output stream ("-") or given `file`
            path = isnothing(file) ? "-" : file
        else
            # set output format to XML and rediret xml to tmp or given file
            if isnothing(file)
                path, io = mktemp(tempdir(), cleanup=true)
                close(io)
            else
                path = file
            end
        end
        scanner(_forcexml(path))
    end

    # recreate Cmd in case it has been altered since initial creation
    scanner.cmd = Cmd(scanner)
    @info scanner.cmd

    runctx = (stdout = scanner.stdout, stderr = scanner.stderr)
    if !interactive
        runctx = (stdout = IOBuffer(), stderr = scanner.stderr)
    end
    raw = Base.run(pipeline(scanner.cmd; runctx...), wait=true)

    output = interactive ? read(path, String) : String(take!(runctx.stdout))
    if !scanner.debug && scanner.xml
        # build scan output as type `sink`, default is Scan
        output = Marshalling.unmarshall(sink, output)
    end
    if (scanner.xml && path != "-") && autoremove
        @async rm(path)
    end
    return output
end
