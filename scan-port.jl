using Sockets, Dates, Printf, JSON3, Base.Threads, ArgParse

const GREEN = "\033[32m"
const RED = "\033[31m"
const RESET = "\033[0m"
const COMMON_PORTS = Dict(
    21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
    53 => "DNS", 80 => "HTTP", 110 => "POP3", 143 => "IMAP",
    443 => "HTTPS", 445 => "SMB", 3389 => "RDP", 8080 => "HTTP-Alt"
)

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

function get_service_name(port::Int)::String
    get(COMMON_PORTS, port, "Unknown")
end

function is_port_open(host::String, port::Int; timeout::Float64=3.0)::Bool
    try
        # Use Sockets.connect with a timeout
        sock = Sockets.connect(host, port, timeout)
        close(sock)
        return true
    catch e
        if isa(e, InterruptException)
            rethrow() # Allow user interrupt to stop the scan
        else
            return false
        end
    end
end

function banner_grab(host::String, port::Int; max_kb::Int=2)::String
    buf = IOBuffer()
    try
        s = Sockets.connect(host, port, 3.0)
        max_b = max_kb * 1024
        bytes_read = 0
        while bytes_read < max_b
            if bytesavailable(s) > 0
                chunk = readavailable(s)
                write(buf, chunk)
                bytes_read += length(chunk)
            else
                yield() # Yield to other tasks
            end
        end
        close(s)
    catch e
        return "Error grabbing banner: $(sprint(showerror, e))"
    end
    return String(take!(buf))
end

function run_action(tpl::String, host::String, port::Int)::String
    script = replace(tpl, "{host}" => host, "{port}" => string(port))
    cmd = `/bin/sh -c $script` # JULIA OP
    try
        readchomp(cmd)
    catch e
        "ACTION_ERROR: $(sprint(showerror, e))"
    end
end

function scan_port(host::String, port::Int; timeout::Float64=3.0, grab::Bool=false, action::Union{String, Nothing}=nothing)
    open = is_port_open(host, port; timeout=timeout)
    if open
        service = get_service_name(port)
        banner = grab ? banner_grab(host, port) : nothing
        act_out = action !== nothing ? run_action(action, host, port) : nothing
        (port=port, status="open", service=service, banner=banner, action_output=act_out)
    else
        (port=port, status="closed", service=nothing, banner=nothing, action_output=nothing)
    end
end

function parse_args()
    p = ArgParseSettings(description="Port scanner ")
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
        "--grab", "-g"
        help = "Banner grab"
        action = :store_true
        "--action", "-a"
        help = "Shell template {host} {port} for open ports"
        default = nothing
        "--json-output", "-j"
        help = "Output results as JSON only"
        action = :store_true
    end
    parse_args(p)
end

function main()
    args = parse_args()
    host = args["host"]
    ports_to_scan = lowercase(args["ports"]) == "all" ? collect(1:65535) : parse_port_range(args["ports"])
    to = args["timeout"]
    grab = args["grab"]
    action = args["action"]
    json_only = args["json-output"]

    results = Vector{NamedTuple}()
    lock_results = ReentrantLock()

    total_ports = length(ports_to_scan)
    println("Starting scan of $total_ports ports on $host...")
    start_time = now()

    
    port_channel = Channel{Int}(total_ports)
    for port in ports_to_scan
        put!(port_channel, port)
    end

    tasks = [Threads.@spawn begin
                while !isempty(port_channel)
                    port = take!(port_channel)
                    res = scan_port(host, port; timeout=to, grab=grab, action=action)
                    @lock lock_results push!(results, res)
                end
            end for _ in 1:Threads.nthreads()]

    for t in tasks
        wait(t)
    end

    end_time = now()
    duration = canonicalize(end_time - start_time)

    sort!(results, by=x -> x.port)
    open_ports = filter(r -> r.status == "open", results)

    if json_only
        println(JSON3.write(open_ports))
    else
        println("\nScan finished in $(duration). Found $(length(open_ports)) open ports.")
        println("--------------------------------------")
        if isempty(open_ports)
            println("No open ports found.")
        else
            for res in open_ports
                service_str = !isnothing(res.service) ? " ($(res.service))" : ""
                println("$(GREEN)PORT $(res.port)$RESET$(service_str) is $(GREEN)OPEN$RESET")
                if !isnothing(res.banner) && !isempty(strip(res.banner))
                    println("  Banner: " * strip(res.banner))
                end
                if !isnothing(res.action_output) && !isempty(strip(res.action_output))
                    println("  Action Output: " * strip(res.action_output))
                end
            end
        end
        println("--------------------------------------")
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end