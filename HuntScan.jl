module HuntScan
using JSON3, HTTP, Sockets

export hunt_origin

const SUB_PREFIX = ["direct", "origin", "mail", "ftp", "admin", "beta", "old", "staging", "dev", "test", "ns1", "ns2"]

function sub_enum(domain)
    [pre * "." * domain for pre in SUB_PREFIX]
end

function crt_ips(domain)
    try
        r = HTTP.get("https://crt.sh/?q=%25.$domain&output=json", retry=false, readtimeout=8)
        data = JSON3.read(r.body)
        ips = Set{String}()
        for e in data, m in eachmatch(r"(\d+\.\d+\.\d+\.\d+)", e.common_name === nothing ? "" : e.common_name)
            push!(ips, m.captures[1])
        end
        return collect(ips)
    catch
        return String[]
    end
end

function resolve(host)
    try
        return string(getaddrinfo(host))
    catch
        return nothing
    end
end

function hunt_origin(domain)
    ips = Set{String}()
    foreach(x -> push!(ips, x), crt_ips(domain))
    addr = resolve(domain)
    addr === nothing || push!(ips, addr)
    for sub in sub_enum(domain)
        addr = resolve(sub)
        addr === nothing || push!(ips, addr)
    end
    return collect(ips)
end

end 