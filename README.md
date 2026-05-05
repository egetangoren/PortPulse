<div align="center">

```
 ██████╗  ██████╗ ██████╗ ████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
 ██████╔╝██║   ██║██████╔╝   ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
 ██║     ╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
```

**Multi-threaded Port Scanner & Banner Grabber**

A lightweight, socket-level network reconnaissance tool built in Python.  
PortPulse leverages concurrent threading to rapidly scan TCP ports, capture service banners, and identify running services using a local signature database.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge)

</div>

---

> [!CAUTION]
> **⚖️ Legal & Ethical Disclaimer**
>
> This tool is developed **strictly for educational and authorized security testing purposes**. Unauthorized port scanning of networks, systems, or devices that you do not own or have explicit written permission to test is **illegal** and may violate local, national, and international laws including the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and similar legislation worldwide.
>
> **The developer assumes no liability** for any misuse, damage, or legal consequences resulting from the use of this tool. Always obtain proper authorization before conducting any security assessment. Use responsibly.

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage & Examples](#-usage--examples)
- [Example Terminal Output](#-example-terminal-output)
- [JSON Report Format](#-json-report-format)
- [Blue Team Perspective — Detection & Mitigation](#-blue-team-perspective--detection--mitigation)
- [License](#-license)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Multi-threaded Scanning** | Concurrent port scanning powered by Python's `threading` and `queue.Queue`, with user-configurable thread count for maximum efficiency. |
| **Dynamic Banner Grabbing** | Connects to open ports via raw TCP sockets and captures service banners (up to 1024 bytes) within a 2-second timeout window. |
| **Custom Signature Matching** | Identifies services by performing case-insensitive keyword matching against a local `signatures.json` database containing 13+ common port signatures. |
| **Intuitive CLI Interface** | Full `argparse`-powered command-line interface with support for comma-separated ports, port ranges, and custom thread counts. |
| **Colorized Terminal Output** | Beautiful ASCII table output using `tabulate` with color-coded results via `colorama` for enhanced readability. |
| **JSON Report Export** | Export scan results to a structured JSON file with enriched metadata including timestamps, scan duration, and target information. |
| **Robust Error Handling** | Gracefully handles `socket.timeout`, `ConnectionRefusedError`, `PermissionError`, and other exceptions without crashing. |

---

## 📁 Project Structure

```
portpulse/
├── scanner.py          # Core scanning engine, CLI, and output formatting
├── signatures.json     # Local service signature database (port → service mapping)
├── requirements.txt    # External Python dependencies
├── README.md           # Project documentation (this file)
└── .gitignore          # Git ignore rules
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.8** or higher
- `pip` package manager

### Step 1 — Clone the Repository

```bash
git clone https://github.com/egetangoren/PortPulse.git
cd PortPulse
```

### Step 2 — Create a Virtual Environment

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
# macOS / Linux:
source .venv/bin/activate

# Windows:
.venv\Scripts\activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- `tabulate==0.9.0` — ASCII table rendering
- `colorama==0.4.6` — Cross-platform terminal colors

### Step 4 — Verify Installation

```bash
python scanner.py --help
```

---

## 🔧 Usage & Examples

### Basic Syntax

```bash
python scanner.py <target> [options]
```

### CLI Arguments

| Argument | Short | Type | Default | Description |
|----------|-------|------|---------|-------------|
| `target` | — | Positional | *Required* | Target IP address or hostname |
| `--ports` | `-p` | Optional | Common ports | Comma-separated (`22,80,443`) or range (`20-100`) |
| `--threads` | `-t` | Optional | `10` | Number of concurrent scanning threads |
| `--output` | `-o` | Optional | `None` | Save results to a JSON report file |

### Example Commands

```bash
# Scan default common ports on a target
python scanner.py 192.168.1.1

# Scan specific ports with 20 threads
python scanner.py 192.168.1.1 -p 22,80,443,8080 -t 20

# Scan a port range and export results to JSON
python scanner.py 10.0.0.1 -p 1-1000 -t 50 -o report.json

# Scan a hostname with default settings
python scanner.py scanme.nmap.org
```

---

## 🖥️ Example Terminal Output

```
 ██████╗  ██████╗ ██████╗ ████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
 ██████╔╝██║   ██║██████╔╝   ██║   ██████╔╝██║   ██║██║     ███████╗█████╗
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
 ██║     ╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

  Multi-threaded Port Scanner & Banner Grabber
  ─────────────────────────────────────────────

  [*] Target   : 192.168.1.1
  [*] Ports    : 13
  [*] Threads  : 10
  ─────────────────────────────────────────────

  [*] Scanning in progress...

╒════════╤══════════╤═══════════╤═══════════════════════════════════════╕
│ PORT   │ STATUS   │ SERVICE   │ BANNER                                │
╞════════╪══════════╪═══════════╪═══════════════════════════════════════╡
│ 22     │ OPEN     │ SSH       │ SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu │
├────────┼──────────┼───────────┼───────────────────────────────────────┤
│ 80     │ OPEN     │ HTTP      │ N/A                                   │
├────────┼──────────┼───────────┼───────────────────────────────────────┤
│ 443    │ OPEN     │ HTTPS     │ N/A                                   │
├────────┼──────────┼───────────┼───────────────────────────────────────┤
│ 3306   │ OPEN     │ MySQL     │ 8.0.35-0ubuntu0.22.04.1               │
╘════════╧══════════╧═══════════╧═══════════════════════════════════════╛

  [+] 4 open port(s) found.
  [*] Scan completed in 6.38 seconds.
```

---

## 📄 JSON Report Format

When using the `--output` flag, PortPulse generates a structured JSON report:

```json
{
    "scan_metadata": {
        "tool": "PortPulse",
        "target": "192.168.1.1",
        "timestamp": "2026-05-05 19:50:00",
        "scan_duration_seconds": 6.38,
        "timeout_seconds": 2.0
    },
    "summary": {
        "total_open_ports": 4
    },
    "results": [
        {
            "port": 22,
            "status": "open",
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu"
        },
        {
            "port": 80,
            "status": "open",
            "service": "HTTP",
            "banner": ""
        }
    ]
}
```

---

## 🛡️ Blue Team Perspective — Detection & Mitigation

This section is intended for **network administrators**, **SOC analysts**, and **Blue Team professionals** to understand the traffic patterns generated by tools like PortPulse and how to detect and mitigate them.

### Traffic Characteristics

A multi-threaded port scanner like PortPulse produces a **distinctive network footprint** that is relatively straightforward to identify:

| Indicator | Description |
|-----------|-------------|
| **High connection rate** | Multiple TCP SYN packets originating from a single source IP within a very short time window (milliseconds). |
| **Sequential/random port access** | Connection attempts across a wide range of ports on the same destination host — a pattern rarely seen in legitimate traffic. |
| **Short-lived connections** | TCP sessions that are established and immediately torn down (RST or FIN after connect), with minimal to no data exchange. |
| **Banner probe behavior** | Brief data reads immediately after the TCP handshake, followed by abrupt connection termination. |

### Detection Methods

#### 1. IDS/IPS Signatures (Snort / Suricata)

Most modern IDS/IPS systems can detect port scanning activity through threshold-based rules:

```
# Example Suricata rule: Alert on port scan behavior
alert tcp any any -> $HOME_NET any (msg:"Possible TCP Port Scan Detected"; \
  flags:S; threshold:type threshold, track by_src, count 20, seconds 5; \
  classtype:attempted-recon; sid:1000001; rev:1;)
```

This rule triggers when a single source IP sends **20 or more SYN packets within 5 seconds** — a strong indicator of automated scanning.

#### 2. Firewall Log Analysis

Monitor firewall logs (e.g., `iptables`, `pf`, or enterprise firewalls) for:
- A single source IP generating connection attempts to **10+ distinct destination ports** within a short interval.
- A high ratio of **rejected/dropped connections** vs. established sessions from the same source.

```bash
# Example: Analyzing iptables logs for scan patterns
grep "DPT=" /var/log/syslog | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

#### 3. NetFlow / sFlow Analysis

Aggregate flow data to identify anomalies:
- Source IPs with an unusually **high number of unique destination port flows**.
- Sessions with **zero or near-zero byte counts** (indicative of connection-only probes).

### Mitigation Strategies

| Strategy | Implementation |
|----------|---------------|
| **Rate Limiting** | Configure firewall rules to limit the number of new TCP connections per source IP per second (e.g., `iptables -m limit --limit 10/sec`). |
| **Port Knocking** | Implement port knocking sequences to hide sensitive services. Ports remain closed until the correct sequence of connection attempts is received. |
| **Network Segmentation** | Isolate critical services (databases, admin panels) in separate VLANs with strict access control lists (ACLs) to minimize exposure. |
| **Honeypots & Tarpits** | Deploy honeypot services on common ports to detect and slow down scanners. TCP tarpits can hold scanner threads open, reducing scan speed. |
| **Connection Logging** | Enable detailed connection logging on critical hosts and forward logs to a SIEM for real-time correlation and alerting. |
| **Fail2Ban / Dynamic Blocking** | Use tools like `fail2ban` to automatically block source IPs that trigger scan detection thresholds. |

> [!NOTE]
> No single mitigation is foolproof. A layered defense-in-depth approach combining multiple strategies provides the most effective protection against reconnaissance activities.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with 🐍 Python | Designed for Education & Authorized Testing Only**

</div>