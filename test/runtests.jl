using Dates
using JSON
using NMAP
using Test
using XMLDict

@testset "Bulk Options" begin
    scanner = NMAP.Scanner()
    for name in names(NMAP, all=true, imported=false)
        f = getfield(NMAP, name)
        if f isa Function && NMAP.Option in Base.return_types(f)
            ms = methods(f).ms
            for method in ms
                test_scanner = NMAP.Scanner()
                if method.nargs < 2
                    opt = f()
                    test_scanner(opt)
                    len_diff = length(test_scanner.args)
                    cur_len  = length(scanner.args)
                    scanner(opt)
                    @test cur_len + len_diff == length(scanner.args)
                end
            end
        end
    end
end

@testset "XML to Scan" begin
    for (root, dir, files) in walkdir(joinpath(@__DIR__, "resources"))
        for file in files
            input = joinpath(root, file)
            scan  = NMAP.Scan(read(input))
            @test scan isa Scan
            xml   = XMLDict.parse_xml(String(read(joinpath(root, file))))
            @test xml[:args] == scan.args
        end
    end
end
