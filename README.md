# Nmap Enumeration Toolkit

## Dashboard Preview

![Nmap Security Dashboard](screenshots/tcp_security_dashboard.png)

**Automated TCP/UDP enumeration, NSE script inventory, and offline HTML security reporting.**

An educational security automation project for **systems you own or have explicit permission to assess**. Built for isolated Linux/Metasploitable lab environments.

> **Status: v0.1.0 / experimental.** Syntax checks passed; live scanning against your environment has not been independently verified. Review scripts and run the safe mode first.

## Features

- Full TCP port discovery (`-p-`), per-port version identification and service-prefix NSE selection
- Separate `tcp_enum_safe.sh` and `tcp_enum_all.sh` modes
- UDP top-100 port discovery with safe NSE enumeration for confirmed-open ports
- Individual Nmap text reports and scan command logs
- TCP script inventory and per-port available/selected script manifests
- Offline Python HTML reports with rule-based security findings

## Requirements

Linux (tested syntax on Bash), Nmap with NSE scripts under `/usr/share/nmap/scripts/`, Python 3.9+, and privileges for SYN/UDP scanning. No Python packages required.

```bash
sudo apt update
sudo apt install -y nmap python3 git
```

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/nmap-enumeration-toolkit.git
cd nmap-enumeration-toolkit

# Isolated lab target: replace with your authorised IP
sudo bash scripts/tcp_enum_safe.sh 192.168.56.102
python3 scripts/tcp_html_report.py enum_safe_192.168.56.102

sudo bash scripts/udp_enum.sh 192.168.56.102
python3 scripts/udp_html_report.py udp_enum_192.168.56.102
```

Open `enum_safe_192.168.56.102/security_summary.html` and `udp_enum_192.168.56.102/udp_security_summary.html` in your browser.

### Advanced TCP mode — lab only

```bash
sudo bash scripts/tcp_enum_all.sh 192.168.56.102
python3 scripts/tcp_html_report.py enum_all_192.168.56.102
```

**CAUTION:** `tcp_enum_all.sh` selects *all filename-matching NSE scripts*, including brute-force, exploitation and potentially disruptive/DoS checks. It requires an interactive `RUN-ALL` confirmation. Use only in a deliberately isolated, authorised training environment with a VM snapshot. Never run this against public or production systems without a carefully reviewed scope and explicit permission.

## Project layout

```text
nmap-enumeration-toolkit/
├── scripts/
│   ├── tcp_enum_safe.sh
│   ├── tcp_enum_all.sh
│   ├── udp_enum.sh
│   ├── tcp_html_report.py
│   └── udp_html_report.py
├── docs/
│   ├── installation.md
│   └── usage.md
├── examples/
│   └── sample_tcp_report.html
├── screenshots/
├── .gitignore
├── LICENSE
└── README.md
```

## How selection works

TCP scripts are discovered by filename prefix in the local NSE installation (e.g., `ftp-*.nse` for port 21). The safe mode selects scripts with the `safe` category and excludes selected intrusive categories. The all mode selects every matching file, **not every NSE script installed**, and Nmap may skip scripts based on its portrules. The service mapping is port-based, so nonstandard ports may be missed. `tftp-*.nse` is not included with FTP.

The TCP scan directory contains `commands.log`, `script_inventory.tsv`, and `<service><port>_available_scripts.txt` / `_selected_scripts.txt`. **Selected does not mean executed or produced output.**

UDP enumerates the top 100 ports and only follows up on ports Nmap labels `open`; `open|filtered` results remain in discovery output.

## Reports and evidence

HTML findings are based on simple patterns in Nmap text output. Severity is illustrative; findings require manual validation. A service version or CVE reference alone does not prove exploitability.

`examples/sample_tcp_report.html` is a **fictional demonstration**, not a real assessment or confirmed scan output. Replace it with a sanitised, real lab report when ready.

## Security / privacy

Do not commit raw customer scans, passwords, credentials, IP inventories or private network data. `.gitignore` excludes common generated folders but **does not guarantee secrets are excluded**. Review `git status` and staged changes before every push.

## Limitations

- Only common TCP/UDP service prefixes are mapped.
- NSE script categories are imperfect indicators of safety.
- Some NSE scripts need arguments, authentication or prerequisites.
- All-mode can disrupt services, lock accounts, or trigger exploit checks.
- HTML reports are heuristic and should not be used as formal vulnerability verification.
- Running with `sudo` may create root-owned files; use `sudo chown -R "$(id -un)":"$(id -gn)" <report-folder>` if needed.

## License

MIT — see [LICENSE](LICENSE).
