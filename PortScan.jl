module PortScan
using Sockets, Printf, Dates, JSON3, MbedTLS, Base.Threads
using ..HuntScan   # kalau butir konstan di Util, ganti ..Util

export port_scan, DeepResult, deep_probe

const CURL = Sys.iswindows() ? "C:\\Windows\\System32\\curl.exe" : "curl"
const DEEP_TOUT = 5.0
const MAX_BODY  = 100_000

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
                    "not_after" => string(MbedTLS.not_after(cert)))
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
        ipaddr = IPAddr(ip)
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