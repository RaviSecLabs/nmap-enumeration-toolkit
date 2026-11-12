# Installation

Use an isolated lab and an authorised target.

1. Install prerequisites: `sudo apt install nmap python3 git`.
2. Clone the repository and enter its directory.
3. Check NSE scripts exist: `ls /usr/share/nmap/scripts/ftp-*.nse`.
4. Validate Bash syntax: `bash -n scripts/tcp_enum_safe.sh scripts/tcp_enum_all.sh scripts/udp_enum.sh`.
5. Validate Python syntax: `python3 -m py_compile scripts/tcp_html_report.py scripts/udp_html_report.py`.
6. Run a safe scan from the repository root.

Scan reports are written relative to your current working directory. Run Python reporting as your regular user; if sudo-owned results block access, use `sudo chown -R "$(id -un)":"$(id -gn)" enum_safe_TARGET_IP` with the real output folder.
