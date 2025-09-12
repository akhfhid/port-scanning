# Port Scanner (Julia)

**Summary**

Port Scanner is a compact, multi-threaded port-scanning script written in Julia. It can scan a list or range of ports (or all ports 1–65535), perform optional banner grabs, and execute a shell command template for each open port. Output is available in a human-friendly (ANSI-colored) format or as JSON for machine consumption.

---

## Features

* Concurrent port scanning using `Base.Threads`.
* Supports port lists and ranges like `80,443,1000-2000` and the keyword `all` for 1–65535.
* Optional banner grabbing (reads initial bytes from a service).
* Optional shell command template executed for each open port. Template supports `{host}` and `{port}` placeholders.
* Human-readable ANSI-colored output or JSON-only output for piping.
* Built-in mapping for common service ports (e.g., 22 → SSH, 80 → HTTP).

---

## Dependencies

* Julia 1.x (recommended latest stable release)
* Julia packages used (some are built-in):

  * `Sockets` (builtin)
  * `Dates` (builtin)
  * `Printf` (builtin)
  * `JSON3` (install with `] add JSON3`)
  * `Base.Threads` (builtin)
  * `ArgParse` (install with `] add ArgParse`)

---

## Installation

### Clone the repository

Clone your repository from GitHub (replace with your preferred path):

```sh
git clone https://github.com/akhfhid/port-scanning.git
cd port-scanning
```

This repository contains `scan-port.jl` (the scanner script), an example `Makefile`, a `Dockerfile`, and this `README`.

### Install Julia packages

From the Julia REPL in the project folder, run:

```julia
import Pkg
Pkg.add("JSON3")
Pkg.add("ArgParse")
```

### Save/Verify script

Make sure the main script is present and executable (or run it with the `julia` command):

```sh
ls -l scan-port.jl
julia scan-port.jl --help
```

---

## Usage

Basic syntax:

```sh
julia scan-port.jl <host> <ports> [--timeout N] [--grab] [--action "CMD_TEMPLATE"] [--json-output]
```

Important flags:

* `<host>` — target hostname or IP.
* `<ports>` — single ports, ranges, or `all` (e.g. `22,80,443` or `1000-2000` or `all`).
* `--timeout`, `-t` — connection timeout in seconds (default `2.0`).
* `--grab`, `-g` — enable banner grabbing.
* `--action`, `-a` — shell command template executed for open ports. Use `{host}` and `{port}` placeholders.
* `--json-output`, `-j` — print only JSON for open ports.

---

## Examples

1. Scan ports 22, 80 and 443 on `example.com`:

```sh
julia scan-port.jl example.com "22,80,443"
```

2. Scan range 1000–1010 on `192.168.1.10`, banner-grab, output JSON:

```sh
julia scan-port.jl 192.168.1.10 "1000-1010" -g -j
```

3. Scan all ports on `localhost` and echo a message when open ports are found:

```sh
julia scan-port.jl localhost all -a "echo Port {port} on {host} is open"
```

---

## Example outputs

> Note: The following outputs are simulated examples for documentation. Actual results depend on the scanned host.

### Human-readable (ANSI colored)

```
Starting scan of 3 ports on example.com...

Scan finished in 00:00:02.345678. Found 2 open ports.
--------------------------------------
[32mPORT 22[0m (SSH) is [32mOPEN[0m
  Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
[32mPORT 443[0m (HTTPS) is [32mOPEN[0m
  Banner: HTTP/1.1 400 Bad Request
Server: nginx/1.18.0
--------------------------------------
```

### JSON-only (using `--json-output`)

```json
[
  {
    "port": 22,
    "status": "open",
    "service": "SSH",
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "action_output": null
  },
  {
    "port": 443,
    "status": "open",
    "service": "HTTPS",
    "banner": "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.18.0",
    "action_output": null
  }
]
```

---

## How it works (technical)

* `is_port_open` attempts `Sockets.connect(host, port, timeout)` and treats successful connect as an open port.
* `banner_grab` connects and reads up to a configurable number of kilobytes from the socket.
* Concurrency model: create a `Channel{Int}` filled with ports and spawn `Threads.nthreads()` workers which consume from the channel and scan ports.
* Results are collected into a shared vector `results` guarded by a `ReentrantLock` to avoid races.

---

## systemd service example

Create a systemd unit file `/etc/systemd/system/ultra-port-scanner.service` to run the scanner as a simple service. **Only use this on hosts where you have permission.**

```ini
[Unit]
Description=Ultra Port Scanner (Julia)
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/opt/ultra-port-scanner
ExecStart=/usr/bin/julia /opt/ultra-port-scanner/scan-port.jl example.com "22,80,443" -g -j
User=nobody
Group=nogroup
Nice=10

[Install]
WantedBy=multi-user.target
```

Reload systemd and enable/run the unit:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ultra-port-scanner.service
```

Use `sudo journalctl -u ultra-port-scanner.service -f` to inspect output.

---

## Makefile example

A simple `Makefile` to run common tasks:

```makefile
JULIA ?= julia
SCRIPT = scan-port.jl
TARGET = example.com
PORTS = "22,80,443"

.PHONY: scan json grab all

scan:
	$(JULIA) $(SCRIPT) $(TARGET) $(PORTS)

json:
	$(JULIA) $(SCRIPT) $(TARGET) $(PORTS) -j

grab:
	$(JULIA) $(SCRIPT) $(TARGET) $(PORTS) -g

all:
	$(JULIA) $(SCRIPT) localhost all -g -j
```

Run for example `make scan` or `make json`.

---

## Dockerfile example

A minimal Dockerfile that runs the scanner inside a container. This image will run the scanner once (as a `CMD`), so it fits batch/CI usage.

```dockerfile
FROM julia:1.9-bullseye

WORKDIR /opt/ultra-port-scanner

# Copy script
COPY scan-port.jl /opt/ultra-port-scanner/scan-port.jl

# Install necessary Julia packages
RUN julia -e "import Pkg; Pkg.add([\"JSON3\", \"ArgParse\"])"

ENTRYPOINT ["julia", "scan-port.jl"]
# Example default arguments (can be overridden at runtime)
CMD ["example.com", "22,80,443"]
```

Build and run:

```sh
docker build -t ultra-port-scanner .
docker run --rm ultra-port-scanner
# override args
docker run --rm ultra-port-scanner 192.168.1.10 "1000-1010" -g -j
```

---

## Legal & Ethical Notice

Port scanning may be considered intrusive or illegal if performed without permission. Only scan systems and networks you own or have explicit authorization to test. The author is not responsible for misuse of this software.

---

## Development notes & improvements

* Add a CLI option to set the worker thread count (e.g., `--threads`).
* Improve banner extraction for protocols that require an initial request (e.g., HTTP, SMTP) — currently the script only reads unsolicited data.
* Add rate limiting and backoff to avoid triggering intrusion detection systems.
* Consider adding optional TCP SYN scan support via raw sockets (requires elevated privileges) or integrate with `nmap` for more advanced scanning features.

---

© 2025 akhfhid — Repository: akhfhid/port-scanning
