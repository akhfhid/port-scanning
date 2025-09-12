#!/usr/bin/env julia
using Sockets, Dates, Printf, JSON3, Base.Threads, ArgParse

const GREEN = "\033[32m"
const RED = "\033[31m"
const RESET = "\033[0m"

# ---------- tambahan ----------
function parse_port_range(input::String)::Vector{Int}
    ports = Int[]
    for part in split(input, ',')
        if occursin('-', part)
            a, b = split(part, '-')
            append!(ports, parse(Int, a):parse(Int, b))
        else
            push!(ports, parse(Int, part))
        end
    end
    unique(sort(ports))
end

function is_port_open(host, port; timeout=3.0)
    try
        sock = Sockets.connect(host, port; timeout=timeout)
        close(sock)
        return true
    catch
        return false
    end
end

function banner_grab(host, port; max_kb=2)
    buf = IOBuffer()
    try
        s = Sockets.connect(host, port; timeout=3.0)
        max_b = max_kb * 1024
        bytes = 0
        while bytes < max_b
            if bytesavailable(s) > 0
                chunk = readavailable(s)
                write(buf, chunk)
                bytes += length(chunk)
            else
                sleep(0.05)
            end
        end
        close(s)
    catch
    end
    String(take!(buf))
end

function run_action(tpl, host, port)
    script = replace(tpl, "{host}" => host, "{port}" => string(port))
    cmd = `/bin/sh -c $script`
    try
        readchomp(cmd)
    catch e
        "ACTION_ERROR: $(sprint(showerror, e))"
    end
end
# ---------- end tambahan ----------

function scan_port(host, port; timeout=3.0, grab=false, action=nothing)
    open = is_port_open(host, port; timeout=timeout)
    if open
        banner = grab ? banner_grab(host, port) : nothing
        act_out = action !== nothing ? run_action(action, host, port) : nothing
        (port=port, status="open", banner=banner, action_output=act_out)
    else
        (port=port, status="closed", banner=nothing, action_output=nothing)
    end
end

function parse_args()
    p = ArgParseSettings(description="Ultra port scanner (based on your code)")
    @add_arg_table! p begin
        "host"
        help = "Target host"
        required = true
        "ports"
        help = "Port/range e.g. 80,443,1000-2000 or 'all' for 1-65535"
        required = true
        "--timeout", "-t"
        help = "Connect timeout"
        arg_type = Float64
        default = 2.0
        "--threads", "-T"
        help = "Threads"
        arg_type = Int
        default = 200
        "--grab", "-g"
        help = "Banner grab"
        action = :store_true
        "--action", "-a"
        help = "Shell template {host} {port} untuk port terbuka"
        default = nothing
    end
    parse_args(p)
end

function main()
    args = parse_args()
    host = args["host"]
    ports = lowercase(args["ports"]) == "all" ? collect(1:65535) : parse_port_range(args["ports"])
    to = args["timeout"]
    nthr = args["threads"]
    grab = args["grab"]
    action = args["action"]

    results = Vector{NamedTuple}()
    lock_results = ReentrantLock()

    @threads for _ in 1:nthr
        while true
            port = nothing
            @lock lock_results (isempty(ports) ? nothing : (port = popfirst!(ports)))
            port === nothing && break
            res = scan_port(host, port; timeout=to, grab=grab, action=action)
            @lock lock_results push!(results, res)
        end
    end

    sort!(results, by=x -> x.port)
    println(JSON3.write(results))  # JSON murni
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end