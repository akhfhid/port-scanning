using Printf, Dates, JSON3
include("HuntScan.jl")
using .HuntScan
include("PortScan.jl")
using .PortScan

const GREEN = "\033[32m"
const RED = "\033[31m"
const RESET = "\033[0m"

function parse_ports(s::String)
    s == "all" && return 1:65535
    out = Int[]
    for chunk in split(s, ',', keepempty=false)
        occursin('-', chunk) ? push!(out, parse.(Int, split(chunk, '-'))...) : push!(out, parse(Int, chunk))
    end
    unique!(sort!(out))
end

function main()
    length(ARGS) < 2 && (println("Usage: julia --threads N main.jl DOMAIN PORTS [timeout]"); exit(1))
    domain = ARGS[1]
    ports = parse_ports(ARGS[2])
    timeout = length(ARGS) >= 3 ? parse(Float64, ARGS[3]) : 2.0
    println("[*] Hunt origin for $domain …")
    ips = hunt_origin(domain)
    isempty(ips) && (println("[-] No IP found"); exit(0))
    println("[+] IPs: ", join(ips, ", "))

    println("\n[*] Scan ports ", join(ports, ", "), " …")
    results = port_scan(ips, ports, timeout)

    tot_open = 0
    for (ip, res) in results
        println("\n$ip")
        for (p, open, dr) in res
            print(open ? GREEN : RED, lpad(p, 5), RESET, " ")
            open && (tot_open += 1)
        end
        println()
        for (p, open, dr) in res
            open || continue
            print(GREEN * lpad(string(p), 5) * RESET * "  ")
            if dr !== nothing
                print(dr.service, " | ", dr.extras)
            end
            println()
        end
    end
    println("\nDone — $tot_open open total")
    out = Dict(ip => Dict(string(p) => (open ? (dr === nothing ? "open" : dr.extras) : "closed")
                          for (p, open, dr) in res) for (ip, res) in results)
    file = "hunt_$(domain)_$(Dates.format(now(), "yyyy-mm-dd_HH-MM-SS")).json"
    open(file, "w") do f
        JSON3.pretty(f, out)
    end
    println("Saved: ", file)
end

if basename(PROGRAM_FILE) == "main.jl"
    main()
end