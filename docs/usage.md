# Usage

Replace `192.168.56.102` with an IP address belonging to your isolated authorised lab.

```bash
sudo bash scripts/tcp_enum_safe.sh 192.168.56.102
python3 scripts/tcp_html_report.py enum_safe_192.168.56.102

sudo bash scripts/udp_enum.sh 192.168.56.102
python3 scripts/udp_html_report.py udp_enum_192.168.56.102
```

For all matching TCP NSE scripts (isolated disposable lab only):

```bash
sudo bash scripts/tcp_enum_all.sh 192.168.56.102
python3 scripts/tcp_html_report.py enum_all_192.168.56.102
```

The all-mode script prompts for `RUN-ALL`. It may invoke disruptive scripts, brute force and exploit checks. Read the script selection before use.

The TCP scripts also accept `--skip-discovery` only if a prior `enum_TARGET/discovery.gnmap` exists in the current directory. Normally leave this option out.

### Understanding output

- `discovery.txt`: open-port discovery output
- `ftp21.txt`: per-port Nmap result (when port 21 is found)
- `ftp21_available_scripts.txt`: matching installed NSE scripts
- `ftp21_selected_scripts.txt`: scripts passed to Nmap
- `commands.log`: exact commands requested
- `script_inventory.tsv`: counts of available and selected scripts
- `security_summary.html`: TCP findings report

A script may be selected but skipped by Nmap, or run without producing visible output.
