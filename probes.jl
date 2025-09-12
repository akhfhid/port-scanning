# probes.jl – compact nmap-service-probes loader + matcher
# source: condensed nmap 7.94 service-fingerprints + custom additions
# format: Dict(port => Vector{Tuple{String,Regex}})  [probe, match]

const PROBE_RULES = Dict{Int,Vector{Tuple{String,Regex}}}()

function compile_probe(raw::String)
    probe = replace(raw, "\\r" => "\r", "\\n" => "\n", "\\0" => "\0", "\\t" => "\t")
    probe
end

function compile_match(line::String)
    m = match(r"m/(.+)/", line)
    m === nothing && return nothing
    re_str = m.captures[1]
    re_str = replace(re_str, "\\/" => "/")
    try
        Regex(re_str)
    catch
        nothing
    end
end

let rules = raw"""
# nmap-service-probes excerpt – expand freely
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d\d\d| p/HTTP/
match nginx m|^HTTP/1\.[01] \d\d\d.*Server: nginx| p/nginx/
match apache m|^HTTP/1\.[01] \d\d\d.*Server: Apache| p/Apache/
match iis m|^HTTP/1\.[01] \d\d\d.*Server: Microsoft-IIS| p/IIS/

Probe TCP SSH q||
match ssh m|^SSH-([\d.]+)-| p/OpenSSH/ v/$1/

Probe TCP FTP q||
match ftp m|^220 ([\w._-]+) FTP| p/FTP/ h/$1/

Probe TCP SMTP q|EHLO scanner\r\n|
match smtp m|^220 ([\w._-]+) ESMTP| p/ESMTP/ h/$1/

Probe TCP MySQL q||
match mysql m|^\x0a([\d.]+)\x00| p/MySQL/ v/$1/

Probe TCP PostgreSQL q||
match postgresql m|^E\x00\x00\x00\x0a| p/PostgreSQL/

Probe TCP RDP q||
match rdp m|^\x03\x00\x00\x13\x0e\xd0\x00\x00\x12| p/RDP/

Probe TCP SMB q|^\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00|
match smb m|^\x00\x00\x00\x85\xff\x53\x4d\x42\x72| p/SMB/

Probe TCP DNS q||
match dns m|^\x00[\x00-\x1f]\x85\x00\x00\x00\x00\x00\x00\x00\x00| p/DNS/

Probe TCP HTTPS q||
match https m|^\x16\x03\x01| p/TLS/
"""

    port_map = Dict{Int,Vector{Tuple{String,Regex}}}()
    current_probe = ""
    current_port = 0
    for line in split(rules, '\n'; keepempty=false)
        line = strip(line)
        startswith(line, '#') && continue
        if startswith(line, "Probe TCP ")
            m = match(r"Probe TCP (\w+) q\|([^|]*)\|", line)
            m === nothing && continue
            current_probe = compile_probe(m.captures[2])

            probe_name = m.captures[1]
            current_port = probe_name == "GetRequest" ? 80 :
                           probe_name == "SSH" ? 22 :
                           probe_name == "FTP" ? 21 :
                           probe_name == "SMTP" ? 25 :
                           probe_name == "MySQL" ? 3306 :
                           probe_name == "PostgreSQL" ? 5432 :
                           probe_name == "RDP" ? 3389 :
                           probe_name == "SMB" ? 445 :
                           probe_name == "DNS" ? 53 :
                           probe_name == "HTTPS" ? 443 : 0
            current_port == 0 && continue
            haskey(port_map, current_port) || (port_map[current_port] = Tuple{String,Regex}[])
        elseif startswith(line, "match ")
            current_port == 0 && continue
            re = compile_match(line)
            re === nothing && continue
            push!(port_map[current_port], (current_probe, re))
        end
    end
    # assign to const
    for (p, vec) in port_map
        PROBE_RULES[p] = vec
    end
end

function match_probe(port::Int, banner::String)
    rules = get(PROBE_RULES, port, Tuple{String,Regex}[])
    for (probe, re) in rules
        m = match(re, banner)
        m !== nothing && return m.captures[1]
    end
    nothing
end

export PROBE_RULES, match_probe