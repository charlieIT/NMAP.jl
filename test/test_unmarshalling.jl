using JSON
using NMAP: NMAP, Marshalling
using Test
using StructTypes
using XMLDict

filepath = joinpath(resources, "example.xml")

@testset "Unmarshall to sink" begin
    xml     = read(filepath)
    iscan   = NMAP.Scan(xml)
    scan    = Marshalling.unmarshall(NMAP.Scan, read(filepath, String))
    @test scan.xml == iscan.xml

    xmlstr = read(filepath, String)
    @test Marshalling.unmarshall(String, xmlstr) == xmlstr

    xmld    = Marshalling.unmarshall(Dict, xmlstr)
    xmljson = Marshalling.unmarshall(NMAP.Json, xmlstr)
    @test JSON.json(xmld) == xmljson

    xmldict = XMLDict.parse_xml(read(filepath, String))
    xmlstr  = String(XMLDict.dict_xml(xmldict))
    @test Marshalling.unmarshall(String, xmldict)   == xmlstr
    @test Marshalling.unmarshall(Dict,   xmldict)   == XMLDict.xml_dict(xmldict)
    @test Marshalling.unmarshall(NMAP.Json, xmldict)== JSON.json(XMLDict.xml_dict(xmldict))
end

@testset "Unmarshall to Leaf types" begin
    xmldict  = XMLDict.parse_xml(read(filepath, String))
    testscan = NMAP.Scan(xmldict)

    leafs = []
    for name in names(NMAP, all=true, imported=false)
        if  getfield(NMAP, name) isa DataType &&
            getfield(NMAP, name) <: NMAP.Leaf

            push!(leafs, getfield(NMAP, name))
        end
    end
    @testset "Unmarshall Scan Leaf types" begin
        scanleafs = filter(x->x in NMAP.Scan.types, leafs)
        typemap   = Dict([name=>type for (name, type) in zip(fieldnames(Scan), Scan.types) if type in scanleafs])
        revmap    = Dict([type=>name for (name, type) in typemap])
        testscan  = Scan(read(filepath))

        for (k,v) in xmldict
            if any(x->x in keys(typemap), [k, Symbol(k)])
                leaf   = get(typemap, Symbol(k), get(typemap, k, k))
                object = StructTypes.construct(leaf, v)

                field = Marshalling.getfield(Scan, k)
                comparator = Base.getproperty(testscan, field)

                @test !isdiff(object, comparator)
            end
        end
    end
end
