module ServiceId

using Sockets, Dates, JSON3, CodecZlib, MbedTLS
export identify!, save_json, save_csv

const CURL_TIMEOUT = 5 
const TLS_TIMEOUT = 5

struct Service
    port::Int
    proto::String       
    banner::String       
    tls::Union{Nothing,Dict} 
    http::Union{Nothing,Dict}  
    ssh::Union{Nothing,String} 
end
Service(p, b) = Service(p, "tcp", b, nothing, nothing, nothing)
function cert_info(ip::IPAddr, port::Int)
    try
        ctx = MbedTLS.SSLContext()
        sock = Sockets.TCPSocket()
        connect(sock, ip, port)
        MbedTLS.set_bio!(ctx, sock)
        MbedTLS.handshake(ctx)
        cert = MbedTLS.get_peer_cert(ctx)
        close(sock)
        subj = MbedTLS.get_subject(cert)
        issuer = MbedTLS.get_issuer(cert)
        not_before = MbedTLS.get_not_before(cert)
        not_after = MbedTLS.get_not_after(cert)
        san = MbedTLS.get_san(cert)
        return Dict(
            :subject => subj,
            :issuer => issuer,
            :not_before => string(not_before),
            :not_after => string(not_after),
            :san => san
        )
    catch
        return nothing
    end
end
function http_meta(ip::IPAddr, port::Int; https=false)
    scheme = https ? "https" : "http"
    url = "$scheme://$ip:$port"
    hdr = try
        read(`curl -s --max-time $CURL_TIMEOUT -I $url`, String)
    catch
        ""
    end
    body = try
        read(`curl -s --max-time $CURL_TIMEOUT -L $url`, String)
    catch
        ""
    end
    title = match(r"(?i)<title[^>]*>(.*?)</title>", body)
    robots = try
        read(`curl -s --max-time $CURL_TIMEOUT $url/robots.txt`, String)
    catch
        ""
    end
    server = match(r"(?i)Server:\s*([^\r\n]+)", hdr)
    Dict(
        :title => title ≡ nothing ? "" : title.captures[1],
        :server => server ≡ nothing ? "" : strip(server.captures[1]),
        :robots => robots
    )
end

function ssh_version(ip::IPAddr, port::Int)
    sock = Sockets.TCPSocket()
    try
        connect(sock, ip, port)
        buf = readavailable(sock)
        close(sock)
        m = match(r"SSH-([^\r\n]+)", String(buf))
        m ≡ nothing ? "" : m.captures[1]
    catch
        ""
    end
end

function identify!(svc::Service, ip::IPAddr)
    port = svc.port
    if port ∈ (443, 8443, 993, 995, 636)
        svc.tls = cert_info(ip, port)
        svc.http = http_meta(ip, port; https=true)
    elseif port ∈ (80, 8080, 8000, 3000, 5000)
        svc.http = http_meta(ip, port; https=false)
    elseif port == 22
        svc.ssh = ssh_version(ip, port)
    end
    svc
end

function save_json(results::Vector{Service}, file="scan.json")
    open(file, "w") do f
        JSON3.write(f, results)
    end
end
function save_csv(results::Vector{Service}, file="scan.csv")
    open(file, "w") do f
        println(f, "port,proto,banner,tls,http_title,ssh_version")
        for r in results
            println(f, "$(r.port),$(r.proto),$(r.banner),$(r.tls≠nothing),$(r.http≠nothing ? r.http[:title] : ""),$(r.ssh≡nothing ? "" : r.ssh)")
        end
    end
end

end # module