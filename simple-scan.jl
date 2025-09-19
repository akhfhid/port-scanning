#!/usr/bin/env julia
# simple-scan.jl — versi sederhana: hanya output ke terminal
# Cara pakai:
#   julia --threads 8 simple-scan.jl HOST PORTS [--timeout N] [--threads N]
# NOTE: Jumlah thread sesungguhnya diatur lewat `julia --threads N`.
#       Opsi --threads hanya dibaca untuk informasi/tampil di output.

using Sockets, Printf, Dates
using Base.Threads: @threads, nthreads

const GREEN = "\033[32m"
const RED = "\033[31m"
const RESET = "\033[0m"
const DEFAULT_TIMEOUT = 2.0

function parse_ports(s::String)
    s == "all" && return collect(1:65535)
    out = Int[]
    for chunk in split(s, ',', keepempty=false)
        if occursin('-', chunk)
            a,b = split(chunk,'-')
            append!(out, parse(Int,a):parse(Int,b))
        else
            push!(out, parse(Int, chunk))
        end
    end
    unique!(sort!(out))
end

function parse_cli()
    if length(ARGS) < 2
        println("Usage: julia --threads N simple-scan.jl HOST PORTS [--timeout N] [--threads N]")
        exit(1)
    end
    host = ARGS[1]
    ports = parse_ports(ARGS[2])
    timeout = DEFAULT_TIMEOUT
    tcount = nthreads()   # jumlah thread runtime (ditentukan oleh julia --threads)
    i = 3
    while i <= length(ARGS)
        tok = ARGS[i]
        if tok == "--timeout"
            if i+1 > length(ARGS)
                error("Missing value for --timeout")
            end
            timeout = parse(Float64, ARGS[i+1]); i += 2; continue
        elseif tok == "--threads"
            if i+1 > length(ARGS)
                error("Missing value for --threads")
            end
            tcount = parse(Int, ARGS[i+1]); i += 2; continue
        else
            error("Unknown option: $tok")
        end
    end
    return host, ports, timeout, tcount
end

const PROBE_DB = Dict(
    80  => ("GET / HTTP/1.0\r\n\r\n", r"Server:\s*(.+)"),
    22  => ("", r"SSH-(.+)"),
    21  => ("", r"220(.+)FTP"),
    25  => ("EHLO scanner\r\n", r"220(.+)")
)

function try_connect(ip::IPAddr, port::Int, timeout::Float64)
    sock = Sockets.TCPSocket()
    try
        connect(sock, ip, port; connect_timeout=timeout)
        close(sock)
        return true
    catch e
        close(sock)
        return false
    end
end

function grab_banner(sock, port, timeout)
    probe = get(PROBE_DB, port, ("", r""))[1]
    try
        if !isempty(probe)
            try
                write(sock, probe)
            catch
            end
        end
        buf = UInt8[]
        t0 = time()
        while time() - t0 < timeout && length(buf) < 4096
            if bytesavailable(sock) > 0
                append!(buf, readavailable(sock))
            else
                sleep(0.01)
            end
        end
        try close(sock) catch end
        return String(buf)
    catch
        try close(sock) catch end
        return ""
    end
end

function scan_one(ip, port, timeout)
    sock = try_connect(ip, port, timeout)
    if sock === nothing
        return false, ""
    end
    banner = grab_banner(sock, port, timeout)
    return true, banner
end

function normalize_addrs(x)
    if x === nothing
        return AddrInfo[] 
    elseif isa(x, AbstractVector)
        return x
    else
        return [x]
    end
end

function main()
    host_arg, ports, timeout, requested_threads = parse_cli()
    host = replace(host_arg, r"^https?://"i => "")
    addrs_raw = try
        getaddrinfo(host, Sockets.AF_INET)
    catch
        try
            getaddrinfo(host)
        catch
            nothing
        end
    end
    addrs = normalize_addrs(addrs_raw)

    if isempty(addrs)
        error("Could not resolve host: $host (getaddrinfo returned nothing)")
    end

    chosen = addrs[1]
    ip = if hasproperty(chosen, :addr)
        chosen.addr
    else
        chosen
    end

    println("Scanning $(length(ports)) ports on $(host) -> $(ip) with timeout=$(timeout)s")
    println("Julia threads runtime: $(nthreads()); requested (from --threads arg): $requested_threads")
    println("Note: untuk benar-benar mengubah jumlah thread, jalankan julia dengan --threads N")

    results = Vector{Tuple{Int,Bool,String}}(undef, length(ports))

        @threads for i in 1:length(ports)
        p = ports[i]
        open, banner = scan_one(ip, p, timeout)
        results[i] = (p, open, banner)
    end
    open_cnt = count(x -> x[2], results)
    println("\nDone — $open_cnt open ports")
    for (p, open, banner) in sort(results, by = x->x[1])
        if !open
            continue
        end
        b = replace(strip(banner), '\n' => " ")
        display_banner = length(b) > 200 ? b[1:200]*"..." : b
        println(GREEN * lpad(string(p),5) * RESET * "  " * display_banner)
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
