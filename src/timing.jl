"""

-T paranoid|sneaky|polite|normal|aggressive|insane

See also: [Nmap Timing and Performance](https://nmap.org/book/man-performance.html)
"""
@enum Timing begin
    paranoid    = 0
    sneaky      = 1
    polite      = 2
    normal      = 3
    aggressive  = 4
    insane      = 5
end

const AllowedTimings = Union{Timing, Int}

function timingtemplate(timing::AllowedTimings) :: Option
    @assert Int(timing) in Int.(instances(Timing)) "Timing template values range from 0 to 5"
    return Option(
        function(scan::Scanner)
            push!(scan.args, string("-T", Int(timing)))
        end
    )
end
