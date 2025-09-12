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

Ensure scan-port.jl and probes.jl are in the same directory.
3. Install Julia Packages
The script automatically installs required packages on first run. To install manually:
julia -e 'import Pkg; Pkg.add(["JSON3", "LRUCache", "TOML", "CodecZlib", "MbedTLS"])'

4. Set Up Optional Services

Redis: For CVE caching, set the REDIS_URL environment variable:export REDIS_URL=redis://localhost:6379

Ensure a Redis server is running (e.g., via Docker: docker run -d -p 6379:6379 redis).
Shodan: For passive reconnaissance, set the SHODAN_KEY environment variable:export SHODAN_KEY=your_shodan_api_key

Obtain a key from shodan.io.

5. Verify Setup
Check the help menu:
julia scan-port.jl -h


Usage
Run the script with:
julia scan-port.jl HOST PORTS [OPTIONS]


HOST: Target hostname or IP address.
PORTS: Ports to scan (e.g., 80,443, 1000-2000, or all for 1–65535).
OPTIONS:
-t, --timeout SEC: Connection timeout in seconds (default: 2.0).
-j, --json: Output results in JSON format only.
-c, --csv FILE: Write results to a CSV file.
-H, --html FILE: Write results to an HTML report.
-n, --nessus FILE: Write results to a Nessus XML file.
-r, --resume FILE: Resume scan from a saved state (default: scan-port.resume).
-p, --passive: Enable passive reconnaissance (crt.sh, Shodan).
-6, --ipv6: Force IPv6 resolution.
-v, --verbose: Enable verbose output.



Examples

Vulnerability Scan with CVE Lookup:

julia scan-port.jl example.com "22,80,443" -p


Web Security Assessment with JSON Output:

julia scan-port.jl 192.168.1.10 "80,443,8080" -j


Compliance Report in Nessus XML:

julia scan-port.jl example.com "443" -n report.nessus


Resume a Large Scan:

julia scan-port.jl example.com all -r scan-port.resume


Passive Recon with HTML Output:

julia scan-port.jl example.com "443" -p -H report.html


Example Outputs
Human-Readable (ANSI-Colored)
Scanning 3 ports on 93.184.216.34
Done – 2 open ports
22  SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
443  HTTP/1.1 200 OK

JSON Output (--json)
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

Nessus XML Output (--nessus report.nessus)
<NessusClientData_v2>
<Report name="scan-port">
  <ReportHost name="93.184.216.34">
    <ReportItem port="22" svcName="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3" severity="0">
      <description>{"cves":[{"id":"CVE-2021-28041","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-28041","desc":"OpenSSH vulnerability allowing..."}]}</description>
    </ReportItem>
  </ReportHost>
  <ReportHost name="93.184.216.34">
    <ReportItem port="443" svcName="HTTP/1.1 200 OK" severity="0">
      <description>{"cves":[],"cert":{"subject":"CN=example.com","issuer":"C=US, O=Let's Encrypt","serial":"0123456789ABCDEF","not_before":"2025-01-01T00:00:00","not_after":"2025-04-01T00:00:00","san":["example.com","www.example.com"],"sig_alg":"SHA256withRSA"},"ja3_s":"ja3_placeholder","tech":["nginx"],"headers":{"Server":"nginx/1.18.0"},"favicon":"a1b2c3d4e5f67890","robots":"User-agent: *\nDisallow: /admin/","title":"Example Domain","shodan":{"os":"Ubuntu","ports":[80,443]}}</description>
    </ReportItem>
  </ReportHost>
</Report>
</NessusClientData_v2>

CSV Output (--csv output.csv)
port,ip,banner,cves
22,93.184.216.34,SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3,1
443,93.184.216.34,HTTP/1.1 200 OK,0

HTML Output (--html report.html)
<html><head><style>body{font-family:monospace}</style></head><body>
<h1>scan-port report</h1><table border=1>
<tr><th>port</th><th>service</th><th>info</th></tr>
<tr><td>22</td><td>SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3</td><td>{"cves":[{"id":"CVE-2021-28041","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-28041","desc":"OpenSSH vulnerability allowing..."}]}</td></tr>
<tr><td>443</td><td>HTTP/1.1 200 OK</td><td>{"cves":[],"cert":{"subject":"CN=example.com","issuer":"C=US, O=Let's Encrypt","serial":"0123456789ABCDEF","not_before":"2025-01-01T00:00:00","not_after":"2025-04-01T00:00:00","san":["example.com","www.example.com"],"sig_alg":"SHA256withRSA"},"ja3_s":"ja3_placeholder","tech":["nginx"],"headers":{"Server":"nginx/1.18.0"},"favicon":"a1b2c3d4e5f67890","robots":"User-agent: *\nDisallow: /admin/","title":"Example Domain","shodan":{"os":"Ubuntu","ports":[80,443]}}</td></tr>
</table></body></html>


How It Works (Technical)

Concurrency: Uses a Channel{Job} to distribute port scanning tasks across up to 1000 threads, managed by Julia’s Threads module.
Port Scanning: Performs non-blocking TCP connections with Sockets.connect, using a configurable timeout (default: 2 seconds).
Service Probing: Sends protocol-specific probes (defined in probes.jl) and matches responses against regex patterns to identify services like HTTP, SSH, or MySQL.
TLS Analysis: For ports like 443, extracts certificate details (subject, issuer, SAN, etc.) using MbedTLS and computes JA3 fingerprints (placeholder implementation).
HTTP Reconnaissance: Fetches web pages, extracts headers, detects CMS (e.g., WordPress), and computes SHA256 favicon hashes for ports like 80 and 443.
Passive Reconnaissance: Queries crt.sh for subdomains and Shodan for host details, enhancing reconnaissance without direct interaction.
CVE Lookup: Queries the NVD API for CVEs based on service banners, caching results in an LRUCache or Redis for 24 hours.
Output Handling: Stores results in a thread-safe Vector{Result} with a SpinLock, supporting JSON, CSV, HTML, and Nessus XML formats.
Resume Functionality: Saves scan state (host, ports, completed ports) to a file using Serialization, allowing resumption of interrupted scans.


Deployment Instructions
Running as a systemd Service
Create a systemd unit file to run periodic scans on a Linux system. Save as /etc/systemd/system/port-scanner.service:
[Unit]
Description=Port Scanner (Julia)
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/opt/port-scanner
ExecStart=/usr/bin/julia /opt/port-scanner/scan-port.jl example.com "22,80,443" -j -p
Environment="SHODAN_KEY=your_shodan_api_key"
Environment="REDIS_URL=redis://localhost:6379"
User=nobody
Group=nogroup
Nice=10

[Install]
WantedBy=multi-user.target

Reload and enable:
sudo systemctl daemon-reload
sudo systemctl enable --now port-scanner.service

View logs:
sudo journalctl -u port-scanner.service -f

Running in Docker
Use the provided Dockerfile for containerized execution:
FROM julia:1.9-bullseye

WORKDIR /opt/port-scanner
COPY scan-port.jl probes.jl /opt/port-scanner/
RUN julia -e 'import Pkg; Pkg.add(["JSON3", "LRUCache", "TOML", "CodecZlib", "MbedTLS"])'
ENTRYPOINT ["julia", "scan-port.jl"]
CMD ["example.com", "22,80,443", "-p"]

Build and run:
docker build -t port-scanner .
docker run --rm -e SHODAN_KEY=your_key -e REDIS_URL=redis://redis:6379 port-scanner example.com "80,443" -j

For CI/CD integration (e.g., GitHub Actions):
name: Port Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    container: julia:1.9-bullseye
    steps:
      - uses: actions/checkout@v3
      - run: julia -e 'import Pkg; Pkg.add(["JSON3", "LRUCache", "TOML", "CodecZlib", "MbedTLS"])'
      - run: julia scan-port.jl example.com "22,80,443" -j -p
        env:
          SHODAN_KEY: ${{ secrets.SHODAN_KEY }}
          REDIS_URL: redis://redis:6379


Troubleshooting Guide

Package Installation Fails:

Symptom: Errors like Pkg.add failing due to network issues.
Solution: Ensure internet connectivity and retry. Alternatively, install packages manually:julia -e 'import Pkg; Pkg.add(["JSON3", "LRUCache", "TOML", "CodecZlib", "MbedTLS"])'


Check Julia’s package registry status or use a mirror if needed.


Redis Connection Errors:

Symptom: redis_cmd fails with connection refused.
Solution: Verify Redis is running (redis-cli ping) and REDIS_URL is correct (e.g., redis://localhost:6379). Ensure no firewall blocks port 6379.


Shodan API Issues:

Symptom: Passive reconnaissance fails with 401 Unauthorized.
Solution: Verify SHODAN_KEY is set and valid. Test with:curl "https://api.shodan.io/shodan/host/8.8.8.8?key=$SHODAN_KEY"


Obtain a new key from shodan.io if necessary.


Scan Hangs or Times Out:

Symptom: Scan doesn’t complete or ports remain closed.
Solution: Increase --timeout (e.g., -t 5.0) or reduce concurrency by modifying CONCURRENCY in the script. Check network connectivity to the target.


Invalid Port Range:

Symptom: Error like need PORTS or parsing failure.
Solution: Ensure ports are specified correctly (e.g., 80,443, 1000-2000, or all). Avoid invalid characters or spaces.


TLS Parsing Errors:

Symptom: tls_probe fails or returns empty results.
Solution: Verify the target port supports TLS (e.g., 443). Check MbedTLS version and update if needed:julia -e 'import Pkg; Pkg.update("MbedTLS")'






Legal & Ethical Notice
Port scanning and reconnaissance may be considered intrusive or illegal without explicit permission. Only scan systems you own or have authorization to test. The author is not responsible for misuse of this software.

Development Notes & Improvements

Rate Limiting: Add a --rate option to control scan speed and avoid triggering intrusion detection systems.
Custom Probes: Allow users to define custom probes in probes.jl via a configuration file.
JA3 Fingerprinting: Complete the ja3_fingerprint function to compute accurate JA3 hashes.
Error Handling: Enhance robustness for network failures, invalid inputs, and API rate limits.
Performance Tuning: Optimize memory usage for large port ranges and add progress reporting for long scans.


© 2025 akhfhid — Repository: akhfhid/port-scanning