module PortScan
using Sockets, Printf, Dates, JSON3, MbedTLS, Base.Threads
using ..HuntScan   # kalau butir konstan di Util, ganti ..Util

export port_scan, DeepResult, deep_probe

const CURL = Sys.iswindows() ? "C:\\Windows\\System32\\curl.exe" : "curl"
const DEEP_TOUT = 5.0
const MAX_BODY  = 100_000
const WEAK_SSL = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
const WEAK_HTTP = ["Apache/2.2", "Apache/2.4.7", "nginx/1.6", "IIS/6.0", "PHP/5."]
const WEAK_SSH  = ["SSH-2.0-OpenSSH_6.", "SSH-2.0-OpenSSH_7.0"]

function score_tls(cert::Dict)
    !haskey(cert, "not_after") && return 10
    days = (DateTime(cert["not_after"]) - now()).value ÷ (1000*60*60*24)
    days < 0 && return 10   # expired
    days < 30 && return 5   # akan expired
    return 0
end
function banner_weak(ban::String, weaklist)
    any(w -> occursin(w, ban), weaklist) && return 5
    return 0
end
function judge_security(dr::DeepResult)
    score = 0
    issues = String[]
    if dr.service in ["https","tls"]
        tls = get(dr.extras, "tls", Dict())
        score += score_tls(tls)
        vers = get(tls, "tls_version", "")
        vers in WEAK_SSL && (score += 5; push!(issues, "Weak TLS version"))
    end
    if dr.service in ["http","https"]
        srv = get(dr.extras, "server", "")
        score += banner_weak(srv, WEAK_HTTP)
        occursin("PHP/5.", dr.extras["x_powered_by"]) && (score += 3; push!(issues, "PHP 5.x EoL"))
    end
    if dr.service == "ssh"
        ver = get(dr.extras, "version", "")
        score += banner_weak(ver, WEAK_SSH)
    end
    clamp!(score, 0, 10)
    return Dict("score"=>score, "level"=>(score≥7 ? "CRITICAL" : score≥4 ? "WARNING" : "INFO"),
                "issues"=>issues)
end
struct DeepResult
    service::String
    banner::String
    extras::Dict{String,Any}
end

function try_connect(ip::IPAddr, port, to)
    sock = Sockets.TCPSocket()
    try
        connect(sock, ip, port; connect_timeout=to)
        close(sock)
        return true
    catch
        close(sock)
        return false
    end
end

function http_deep(ip, port, use_tls)
    host = string(ip)
    uri  = use_tls ? "https://$host:$port" : "http://$host:$port"
    hdr  = try read(`$CURL -sL --max-time $DEEP_TOUT --compressed -I $uri`, String) catch; "" end
    body = try read(`$CURL -sL --max-time $DEEP_TOUT --compressed $uri`, String)    catch; "" end
    body = body[1:min(end, MAX_BODY)]
    title  = match(r"(?i)<title[^>]*>(.*?)</title>", body)  !== nothing ? strip(match(r"(?i)<title[^>]*>(.*?)</title>", body).captures[1]) : ""
    server = match(r"(?i)server:\s*([^\r\n]+)", hdr)       !== nothing ? strip(match(r"(?i)server:\s*([^\r\n]+)", hdr).captures[1])       : ""
    xpb    = match(r"(?i)x-powered-by:\s*([^\r\n]+)", hdr) !== nothing ? strip(match(r"(?i)x-powered-by:\s*([^\r\n]+)", hdr).captures[1]) : ""
    rob    = try read(`$CURL -sL --max-time 2 $uri/robots.txt`, String) catch; "" end
    extras = Dict("title"=>title, "server"=>server, "x_powered_by"=>xpb, "robots"=>strip(rob)[1:min(end,500)])
    if use_tls
        extras["tls"] = tls_cert(host,port)
    end
    return DeepResult(use_tls ? "https" : "http", hdr * body[1:500], extras)
end

function tls_cert(host, port=443)
    try
        ctx = MbedTLS.SSLContext()
        MbedTLS.set_hostname!(ctx, host)
        sock = Sockets.TCPSocket()
        connect(sock, host, port; connect_timeout=DEEP_TOUT)
        MbedTLS.set_bio!(ctx, sock, sock)
        MbedTLS.handshake(ctx)
        cert = MbedTLS.get_peer_cert(ctx)
        close(ctx); close(sock)
        return Dict("subject"  => MbedTLS.get_subject(cert),
                    "issuer"   => MbedTLS.get_issuer(cert),
                    "san"      => MbedTLS.get_san(cert),
                    "not_before"=> string(MbedTLS.not_before(cert)),
                    "not_after" => string(MbedTLS.not_after(cert))),
                    "tls_version" => string(MbedTLS.get_version(ctx))
    catch e
        return Dict("error"=>string(e))
    end
end

function ssh_deep(ip, port)
    sock = Sockets.TCPSocket()
    try
        connect(sock, ip, port; connect_timeout=DEEP_TOUT)
        banner = readline(sock; keep=true)
        close(sock)
        vers = match(r"SSH-([^\r\n]+)", banner) !== nothing ? strip(match(r"SSH-([^\r\n]+)", banner).captures[1]) : ""
        return DeepResult("ssh", banner, Dict("version"=>vers))
    catch e
        close(sock)
        return DeepResult("ssh", "", Dict("error"=>string(e)))
    end
end

function deep_probe(ip, port)
    if port == 443 || port == 8443
        return http_deep(ip, port, true)
    elseif port == 80 || port == 8080 || port == 8000
        return http_deep(ip, port, false)
    elseif port == 22
        return ssh_deep(ip, port)
    elseif port == 25 || port == 587 || port == 465
        return smtp_deep(ip, port)
    else
        return DeepResult("unknown", "", Dict())
    end
end

function smtp_deep(ip, port)
    sock = Sockets.TCPSocket()
    try
        connect(sock, ip, port; connect_timeout=DEEP_TOUT)
        banner = readline(sock; keep=true)
        close(sock)
        return DeepResult("smtp", banner, Dict())
    catch e
        close(sock)
        return DeepResult("smtp", "", Dict("error"=>string(e)))
    end
end

function port_scan(ips::Vector{String}, ports, to)
    results = Dict{String, Vector{Tuple{Int,Bool,Union{Nothing,DeepResult}}}}()
    for ip in ips
        ipaddr = IPv4(ip)
        # ipaddr = parse(Sockets.IPAddress, ip)
        res = Vector{Tuple{Int,Bool,Union{Nothing,DeepResult}}}(undef, length(ports))
        @threads for i in 1:length(ports)
            p = ports[i]
            open = try_connect(ipaddr, p, to)
            dr   = open ? deep_probe(ipaddr, p) : nothing
            res[i] = (p, open, dr)
        end
        results[ip] = res
    end
    return results
end

end 