Port Scanner (Julia)
Overview
scan-port.jl is a high-performance, multi-threaded port scanner and reconnaissance tool written in Julia. Designed for security researchers and network administrators, it scans specified ports or ranges (up to all 1–65535 ports), performs banner grabbing, service fingerprinting, TLS certificate analysis, and HTTP reconnaissance. It integrates with external services like Shodan and crt.sh for passive reconnaissance and queries the NVD database for CVE lookups. Results can be output in human-readable format (with ANSI colors), JSON, CSV, HTML, or Nessus XML, with resume functionality for interrupted scans.

Features

Concurrent Scanning: Leverages Julia’s multi-threading with a configurable concurrency limit (default: 1000).
Flexible Port Specification: Supports single ports, ranges (e.g., 80,443,1000-2000), or all (1–65535).
Banner Grabbing: Captures service banners for protocols like HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, RDP, SMB, and DNS.
Service Fingerprinting: Identifies services using a compact probe database (probes.jl) inspired by Nmap’s service detection.
TLS Certificate Parsing (Highlighted): Extracts detailed certificate information (subject, issuer, SAN, etc.) and computes JA3 fingerprints for TLS-enabled ports (e.g., 443, 8443), ideal for web security assessments.
HTTP Reconnaissance (Highlighted): Detects web technologies (e.g., WordPress, Drupal), extracts favicon hashes, fetches robots.txt, and parses HTTP headers for ports like 80, 443, 8080, etc.
Passive Reconnaissance: Queries crt.sh for subdomains and Shodan for host details (requires API key).
CVE Lookup: Queries the NVD API for CVEs based on service versions, with caching via LRU or Redis.
Output Formats (Highlighted):
JSON: Machine-readable output for automation and scripting.
Nessus XML: Integrates with vulnerability management tools like Tenable Nessus.
CSV and HTML for reporting and visualization.


Resume Capability: Saves scan progress to a file for resuming interrupted scans.
IPv6 Support: Optional IPv6 scanning with the --ipv6 flag.


Use Cases

Vulnerability Scanning: Identifies open ports, detects service versions, and retrieves associated CVEs from the NVD database to prioritize remediation.
Web Security Assessments: Analyzes TLS certificates and HTTP responses to uncover misconfigurations, outdated software, or exposed administrative interfaces.
Compliance Reporting: Generates Nessus XML reports for integration with vulnerability management platforms, aiding in compliance audits (e.g., PCI DSS, ISO 27001).
Passive Reconnaissance: Uses Shodan and crt.sh to gather intelligence without direct interaction, reducing the risk of detection.


Dependencies

Julia: Version 1.9 or later (recommended: latest stable release).
Julia Packages:
Built-in: Sockets, Dates, Printf, Base.Threads, Serialization, Downloads.
External (installed automatically by the script):
JSON3
LRUCache
TOML
CodecZlib
MbedTLS




Optional Services:
Redis (for CVE caching, specify via REDIS_URL environment variable).
Shodan API (for passive recon, specify via SHODAN_KEY environment variable).




Installation
1. Install Julia
Download and install Julia from julialang.org. Verify installation:
julia --version

Add Julia to your system’s PATH if necessary.
2. Clone or Download the Script
Clone the repository or download scan-port.jl and probes.jl:
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
    "ip": "93.184.216.34",
    "service": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "cves": [
      {
        "id": "CVE-2021-28041",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-28041",
        "desc": "OpenSSH vulnerability allowing..."
      }
    ]
  },
  {
    "port": 443,
    "ip": "93.184.216.34",
    "service": "",
    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
    "cert": {
      "subject": "CN=example.com",
      "issuer": "C=US, O=Let's Encrypt",
      "serial": "0123456789ABCDEF",
      "not_before": "2025-01-01T00:00:00",
      "not_after": "2025-04-01T00:00:00",
      "san": ["example.com", "www.example.com"],
      "sig_alg": "SHA256withRSA"
    },
    "ja3_s": "ja3_placeholder",
    "tech": ["nginx"],
    "headers": {"Server": "nginx/1.18.0"},
    "favicon": "a1b2c3d4e5f67890",
    "robots": "User-agent: *\nDisallow: /admin/",
    "title": "Example Domain",
    "cves": [],
    "shodan": {
      "os": "Ubuntu",
      "ports": [80, 443]
    }
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
Description=Port Scanner (Julia)
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

Reload and enable:
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
CMD ["example.com", "22,80,443", "-p"]

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
