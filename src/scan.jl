const OUTPUT_VERSIONS = ["1.04"]

"""
    Scanner

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

    output::Vector{UInt8}
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
        return new(cmd, args, binpath, stderr, stdout, Vector{UInt8}(), debug, xml)
    end
end

Base.push!(scanner::Scanner,    args...) = [push!(scanner.args, arg) for arg in args]
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
    Scan(scanner::Scanner) ::Scan

Build a `Scan` from a `scanner` with outputs
"""
Scan(scanner::Scanner) = Scan(scanner.output)
function Marshalling.unmarshall(::Type{Scan}, scanner::Scanner)
    # use constructor to simplify API used to create a Scan from an external output
    return Scan(scanner)
end

"""
    Option

Used to group scanner options

An Option will apply or remove options from scanner arguments

Examples

```julia
opt = Option(function(scanner::Scanner) push!(scanner.args, "-someOpt") end)

opt = Option("-someOpt")

opts = Option("-someOpt", "someValue", anotherValue)
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
    Apply `scanner` to `option`

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

"""
    run(scan::Scanner)

Run the `scanner` synchronously and return scan results as a `Scan`

WIP: To redirect formatted output to both an output stream and Base.stdout, set `interactive_output` to false
"""
function run(
        scanner::Scanner;
        interactive_output::Bool = true,
        file::Union{Nothing, String} = nothing,
        auto_remove::Bool = false)

    if scanner.xml
        if !interactive_output
            # deactive interactive output and print results to standard output stream ("-") or given `file`
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
    if scanner.debug || !scanner.xml
        @warn "Scanning in debug mode, scan outputs will not be automatically parsed to a Scan"
    end
    if !interactive_output
        io   = IOBuffer();
        pipe = pipeline(scanner.cmd; stdout=io, stderr=devnull);
        Base.run(pipe)
        raw = String(take!(io))
    else
        raw = Base.run(pipeline(scanner.cmd, stdout=scanner.stdout, stderr=scanner.stderr), wait=true)
    end
    # update scanner with output
    scanner.output = interactive_output ? read(path) : Vector{UInt8}(raw)
    if !scanner.debug && scanner.xml
        # build Scan
        return Marshalling.unmarshall(Scan, scanner)
    end
    return raw
end
