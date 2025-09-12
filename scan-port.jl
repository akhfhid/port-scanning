#!/usr/bin/env julia
# scan-port.jl – next-gen port scanner & recon pipeline
using Sockets, Dates, Printf, JSON3, SHA, CodecZlib, MbedTLS
using Base: @lock
using Base.Threads: SpinLock
using Serialization, Downloads, LRUCache, TOML
const CONCURRENCY = 1000          
const CONNECT_TIMEOUT = 2.0           
const PROBE_TIMEOUT = 5.0
const RETRIES = 2
const BANNER_MAX_BYTES = 4096
const CACHE_TTL = Hour(24)
const REDIS_URL = ENV["REDIS_URL"]  # optional redis://host:6379
const SHODAN_KEY = ENV["SHODAN_KEY"] # optional
# small pure-Julia packages (add via ] add X)
import Pkg;
for p in ("LRUCache", "TOML", "CodecZlib", "MbedTLS", "JSON3")
    Pkg.add(p)  # remove this block if you prefer manual install
end
;
const GREEN = "\033[32m";
const RED = "\033[31m";
const RESET = "\033[0m";
function parse_cli()
    args = Dict{String,Any}()
    i = 1
    function next()
        i += 1
        ARGS[i-1]
    end
    while i <= length(ARGS)
        tok = next()
        if tok == "-h" || tok == "--help"
            println("""
            scan-port.jl  –  fast multi-protocol recon
            Usage:  scan-port.jl HOST PORTS [options]
            PORTS:  80,443,8000-9000  or  all
            Options
              -t, --timeout SEC        connect timeout (def 2)
              -j, --json               JSON output only
              -c, --csv FILE           write CSV
              -H, --html FILE          write HTML report
              -n, --nessus FILE        write .nessus XML
              -r, --resume FILE        resume file
              -p, --passive            query crt.sh + Shodan
              -6, --ipv6               force IPv6
              -v, --verbose
            """)
            exit(0)
        elseif tok == "-t" || tok == "--timeout"
            args["timeout"] = parse(Float64, next())
        elseif tok == "-j" || tok == "--json"
            args["json"] = true
        elseif tok == "-c" || tok == "--csv"
            args["csv"] = next()
        elseif tok == "-H" || tok == "--html"
            args["html"] = next()
        elseif tok == "-n" || tok == "--nessus"
            args["nessus"] = next()
        elseif tok == "-r" || tok == "--resume"
            args["resume"] = next()
        elseif tok == "-p" || tok == "--passive"
            args["passive"] = true
        elseif tok == "-6" || tok == "--ipv6"
            args["ipv6"] = true
        elseif tok == "-v" || tok == "--verbose"
            args["v"] = true
        elseif !haskey(args, "host")
            args["host"] = tok
        elseif !haskey(args, "ports")
            args["ports"] = tok
        else
            error("unknown arg $tok")
        end
    end
    haskey(args, "host") || error("need HOST")
    haskey(args, "ports") || error("need PORTS")
    args
end
function parse_ports(s::String)
    s == "all" && return 1:65535
    out = Int[]
    for chunk in split(s, ','; keepempty=false)
        if occursin('-', chunk)
            a, b = split(chunk, '-')
            append!(out, parse(Int, a):parse(Int, b))
        else
            push!(out, parse(Int, chunk))
        end
    end
    unique!(sort!(out))
end
const CACHE = LRU{String,Vector{Dict}}(; maxsize=1000)
function redis_cmd(cmd)
    isempty(REDIS_URL) && return nothing
    try
        # very small Redis client
        sock = Sockets.connect(split(REDIS_URL, ':')[1],
            parse(Int, split(REDIS_URL, ':')[2]))
        write(sock, cmd * "\r\n")
        line = readline(sock; keep=true)
        close(sock)
        startswith(line, '+') ? strip(line[2:end]) : nothing
    catch
        nothing
    end
end
function cached_cves(keyword)
    kw = replace(lowercase(strip(keyword)), ' ' => "_")
    haskey(CACHE, kw) && return CACHE[kw]
    # try redis
    if !isempty(REDIS_URL)
        raw = redis_cmd("GET cve:$kw")
        if raw !== nothing
            val = JSON3.read(raw)
            CACHE[kw] = val
            return val
        end
    end
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(HTTP.URIs.escapeuri(keyword))&resultsPerPage=5"
    resp = Downloads.download(url, IOBuffer())
    j = JSON3.read(resp)
    out = [Dict("id" => item.cve.ID,
        "url" => "https://nvd.nist.gov/vuln/detail/$(item.cve.ID)",
        "desc" => item.cve.descriptions[1].value)
           for item in j.vulnerabilities]
    CACHE[kw] = out
    if !isempty(REDIS_URL)
        redis_cmd("SETEX cve:$kw $(Int(CACHE_TTL.value)) $(JSON3.write(out))")
    end
    out
end
function crtsh_subdomains(domain)
    url = "https://crt.sh/?q=%.$domain&output=json"
    try
        buf = Downloads.download(url, IOBuffer())
        json = JSON3.read(buf)
        unique([r.name_value for r in json])
    catch
        String[]
    end
end
function shodan_host(ip::String)
    isempty(SHODAN_KEY) && return Dict()
    url = "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_KEY"
    try
        buf = Downloads.download(url, IOBuffer())
        JSON3.read(buf)
    catch
        Dict()
    end
end
async_probe(ip, port, timeout) = @async begin
    sock = Sockets.TCPSocket()
    Sockets.setnonblock(sock, true)
    try
        Sockets.connect(sock, ip, port)
        # wait writable
        t0 = time()
        while time() - t0 < timeout
            if Sockets.check_writable(sock)
                close(sock)
                return (port=port, status=:open)
            end
            yield()
        end
        close(sock)
        return (port=port, status=:closed)
    catch e
        close(sock)
        return (port=port, status=:closed)
    end
end

include("probes.jl")  

const PROBE_DB = Dict(
    80 => ["GET / HTTP/1.0\r\n\r\n", r"Server:\s*(.+)"],
    22 => ["", r"SSH-(.+)"],
    443 => ["", r""], # special TLS handled below
    21 => ["", r"220(.+)FTP"],
    25 => ["EHLO scanner\r\n", r"220(.+)"],
)
function probe_service(ip, port, timeout)
    tmpl = get(PROBE_DB, port, nothing)
    tmpl === nothing && return Dict("banner" => "")
    probe, sig = tmpl
    sock = Sockets.TCPSocket()
    Sockets.setnonblock(sock, true)
    try
        Sockets.connect(sock, ip, port)
        t0 = time()
        while time() - t0 < timeout
            Sockets.check_writable(sock) && break
            yield()
        end
        if !isempty(probe)
            write(sock, probe)
        end
        buf = UInt8[]
        t0 = time()
        while time() - t0 < timeout && length(buf) < BANNER_MAX_BYTES
            if bytesavailable(sock) > 0
                push!(buf, readavailable(sock)...)
            end
            yield()
        end
        close(sock)
        banner = String(buf)
        m = match(sig, banner)
        m === nothing ? Dict("banner" => banner) : Dict("banner" => banner, "match" => m.captures[1])
    catch e
        close(sock)
        Dict("banner" => "")
    end
end

function parse_cert_der(der)
    cert = MbedTLS.CRT(der)
    Dict(
        "subject" => MbedTLS.get_subject(cert),
        "issuer" => MbedTLS.get_issuer(cert),
        "serial" => bytes2hex(MbedTLS.get_serial(cert)),
        "not_before" => string(MbedTLS.not_before(cert)),
        "not_after" => string(MbedTLS.not_after(cert)),
        "san" => split(MbedTLS.get_subject_alt_names(cert), ','),
        "sig_alg" => MbedTLS.get_signature_algorithm(cert)
    )
end
function ja3_fingerprint(hello)
    "ja3_placeholder"
end
function tls_probe(ip, port, timeout)
    sock = Sockets.TCPSocket()
    Sockets.setnonblock(sock, true)
    try
        Sockets.connect(sock, ip, port)
        hello = UInt8[0x16, 0x03, 0x01, 0x00, 0x00] 
        write(sock, hello)
        buf = UInt8[]
        t0 = time()
        while time() - t0 < timeout && length(buf) < 8192
            if bytesavailable(sock) > 0
                push!(buf, readavailable(sock)...)
            end
            yield()
        end
        close(sock)
   
        cert_len = read(buf, 9, 2) |> reverse |> bytes2hex |> x -> parse(Int, x, base=16)
        cert_der = buf[11:11+cert_len-1]
        cert = parse_cert_der(cert_der)
        Dict("cert" => cert, "ja3_s" => ja3_fingerprint(hello))
    catch e
        close(sock)
        Dict()
    end
end
#######################################################################
# --------------------------- HTTP crawler ----------------------------
function http_recon(ip, port, timeout)
    proto = port in (443, 8443) ? "https" : "http"
    base = "$proto://$ip:$port"
    hdrs = ["User-Agent" => "scan-port/1.0"]
    out = Dict("tech" => String[], "headers" => Dict(), "favicon" => "", "robots" => "", "title" => "")
    try
        resp = Downloads.request(base * "/"; timeout=ceil(Int, timeout), method="GET", headers=hdrs)
        out["headers"] = resp.headers
        body = String(read(resp.body))
        m = match(r"<title>(.+?)</title>"i, body)
        out["title"] = m === nothing ? "" : m.captures[1]
        # favicon hash
        fav = Downloads.download(base * "/favicon.ico", IOBuffer())
        out["favicon"] = bytes2hex(sha256(fav))
        # robots
        try
            rob = Downloads.download(base * "/robots.txt", IOBuffer())
            out["robots"] = String(read(rob))
        catch
        end
        occursin("wordpress", body) && push!(out["tech"], "WordPress")
        occursin("drupal", body) && push!(out["tech"], "Drupal")
    catch
    end
    out
end
struct Job
    ip::IPAddr
    port::Int
end
struct Result
    job::Job
    status::Symbol
    svc::Dict
    enum::Dict
end

const QUEUE = Channel{Job}(CONCURRENCY)
const RESULTS = Vector{Result}()
const LOCK = SpinLock()

function worker(timeout, passive)
    for job in QUEUE
        ip, port = job.ip, job.port
        # 1. connectivity
        fut = async_probe(ip, port, timeout)
        r = fetch(fut)
        if r.status != :open
            @lock LOCK push!(RESULTS, Result(job, :closed, Dict(), Dict()))
            continue
        end
        
        svc = probe_service(ip, port, PROBE_TIMEOUT)
        port in (443, 8443, 993, 995, 465) && merge!(svc, tls_probe(ip, port, PROBE_TIMEOUT))
        port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000) && merge!(svc, http_recon(ip, port, PROBE_TIMEOUT))
        product = get(svc, "match", "")
        cves = isempty(product) ? Dict[] : cached_cves(product)
        enum = Dict("cves" => cves)
        
        if passive
            if port == 443
                shod = shodan_host(string(ip))
                merge!(enum, Dict("shodan" => shod))
            end
        end
        @lock LOCK push!(RESULTS, Result(job, :open, svc, enum))
    end
end
function json_out()
    open_res = filter(r -> r.status == :open, RESULTS)
    out = [merge(Dict("port" => r.job.port,
            "ip" => string(r.job.ip),
            "service" => get(r.svc, "banner", "")),
        r.svc, r.enum) for r in open_res]
    JSON3.write(out)
end
function html_out(file)
    open(file, "w") do io
        println(
            io,
            """
 <html><head><style>body{font-family:monospace}</style></head><body>
 <h1>scan-port report</h1><table border=1>
 <tr><th>port</th><th>service</th><th>info</th></tr>
 """
        )
        for r in RESULTS
            r.status != :open && continue
            println(io, "<tr><td>$(r.job.port)</td><td>$(get(r.svc,"banner",""))</td><td>$(JSON3.write(r.enum))</td></tr>")
        end
        println(io, "</table></body></html>")
    end
end
function csv_out(file)
    open(file, "w") do io
        println(io, "port,ip,banner,cves")
        for r in RESULTS
            r.status != :open && continue
            println(io, "$(r.job.port),$(r.job.ip),$(get(r.svc,"banner","")),$(length(get(r.enum,"cves",[])))")
        end
    end
end
function nessus_out(file)
    open(file, "w") do io
        println(
            io,
            """
 <NessusClientData_v2>
 <Report name="scan-port">
 """
        )
        for r in RESULTS
            r.status != :open && continue
            println(
                io,
                """
     <ReportHost name="$(r.job.ip)">
       <ReportItem port="$(r.job.port)" svcName="$(get(r.svc,"banner",""))" severity="0">
         <description>$(JSON3.write(r.enum))</description>
       </ReportItem>
     </ReportHost>
     """
            )
        end
        println(io, "</Report></NessusClientData_v2>")
    end
end
const RESUME_FILE = "scan-port.resume"
function save_state(host, ports, args)
    open(RESUME_FILE, "w") do f
        serialize(f, (host, ports, args, Set((r.job.port for r in RESULTS))))
    end
end
function load_state()
    isfile(RESUME_FILE) || return nothing
    deserialize(RESUME_FILE)
end

function main()
    args = parse_cli()
    host = args["host"]
    ports = parse_ports(args["ports"])
    timeout = get(args, "timeout", 2.0)
    passive = get(args, "passive", false)
    json = get(args, "json", false)
    csv = get(args, "csv", nothing)
    html = get(args, "html", nothing)
    nessus = get(args, "nessus", nothing)
    resume = get(args, "resume", RESUME_FILE)

    # DNS resolution
    ip = if get(args, "ipv6", false)
        getaddrinfo(host, IPv6)
    else
        getaddrinfo(host, IPv4)
    end

    
    done_ports = Set{Int}()
    if isfile(resume)
        prev = load_state()
        if prev !== nothing && prev[1] == host && prev[2] == ports
            done_ports = prev[4]
            @info "Resuming – skipping $(length(done_ports)) already scanned ports"
        end
    end

    # enqueue
    todo = filter(p -> !(p in done_ports), ports)
    @info "Scanning $(length(todo)) ports on $ip"
    @sync begin
        for _ in 1:min(CONCURRENCY, length(todo))
            @async worker(timeout, passive)
        end
        for p in todo
            put!(QUEUE, Job(ip, p))
        end
        close(QUEUE)
    end

    json && (println(json_out()); return)
    csv !== nothing && csv_out(csv)
    html !== nothing && html_out(html)
    nessus !== nothing && nessus_out(nessus)


    open_cnt = count(r -> r.status == :open, RESULTS)
    println("\nDone – $open_cnt open ports")
    for r in RESULTS
        r.status != :open && continue
        println(GREEN * "$(r.job.port)" * RESET * "  $(get(r.svc,"banner",""))")
    end
    save_state(host, ports, args)
end

abspath(PROGRAM_FILE) == @__FILE__ main()