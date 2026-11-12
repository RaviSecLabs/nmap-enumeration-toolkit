#!/usr/bin/env python3
"""Generate an offline HTML dashboard from Nmap UDP normal-output reports."""
import argparse
import collections
import datetime
import html
import pathlib
import re

P = argparse.ArgumentParser(description=__doc__)
P.add_argument('folder', type=pathlib.Path, help='Directory containing Nmap UDP .txt reports')
P.add_argument('-o', '--output', type=pathlib.Path, help='Output HTML file (default: FOLDER/udp_security_summary.html)')
args = P.parse_args()
folder = args.folder
if not folder.is_dir():
    P.error(f'Folder not found: {folder}')
output = args.output or folder / 'udp_security_summary.html'
reports = sorted(p for p in folder.glob('*.txt') if p.resolve() != output.resolve())
if not reports:
    P.error(f'No .txt reports found in {folder}')
commands_file = folder / 'commands.log'
commands = commands_file.read_text(errors='replace').splitlines() if commands_file.exists() else []

# Conservative indicators; matches are leads, not confirmed exploitability.
RULES = [
 ('High', 'SNMP community information disclosed', r'(?i)(community string|community name|snmp-sysdescr|snmp-info)', 'Potential information disclosure through SNMP; verify access controls.'),
 ('Medium', 'DNS recursion may be enabled', r'(?i)recursion appears to be enabled', 'Potential unauthorised recursive DNS use; verify access restrictions.'),
 ('Medium', 'NFS export exposed', r'(?i)(nfs-showmount|/export/|/home/.*\(|/srv/.*\()', 'Export paths may be disclosed; verify client restrictions and permissions.'),
 ('Medium', 'TFTP information disclosed', r'(?i)(tftp-enum|tftp.*(read|write|found))', 'TFTP often lacks authentication; verify exposed files and permissions.'),
 ('Medium', 'Weak cryptographic configuration', r'(?i)(weak cipher|weak algorithm|deprecated|insecure)', 'Review the protocol configuration and validate the finding.'),
 ('Info', 'Service information disclosed', r'(?i)(ntp-info|rpcinfo|dns-nsid|upnp-info|ike-version)', 'Service metadata is visible; review whether exposure is necessary.'),
]
rows = {}
findings = []
port_re = re.compile(r'^\s*(\d+)/udp\s+(open\|filtered|open|filtered|closed)\s+(\S+)(?:\s+(.*))?$', re.I)
script_re = re.compile(r'^\s*\|_?\s*([\w-]+):')
for report in reports:
    text = report.read_text(errors='replace')
    current_ports = []
    for line in text.splitlines():
        m = port_re.match(line)
        if m:
            port, state, service, version = m.groups()
            key = int(port)
            row = rows.setdefault(key, {'state': state, 'service': service, 'version': '', 'files': set(), 'scripts': set(), 'issues': []})
            row['state'] = state
            if service not in ('unknown', 'unknown?'): row['service'] = service
            if version: row['version'] = version.strip()
            row['files'].add(report.name)
            current_ports.append(key)
    if not current_ports:
        match = re.search(r'(\d+)_udp\.txt$', report.name)
        if match:
            key = int(match.group(1))
            rows.setdefault(key, {'state': 'unknown', 'service': 'unknown', 'version': '', 'files': set(), 'scripts': set(), 'issues': []})['files'].add(report.name)
            current_ports = [key]
    # Script output may be nested under host scripts, so only assign when file maps to one port.
    if len(current_ports) == 1:
        key = current_ports[0]
        for line in text.splitlines():
            m = script_re.match(line)
            if m: rows[key]['scripts'].add(m.group(1))
    for severity, title, pattern, impact in RULES:
        matches = [line.strip() for line in text.splitlines() if re.search(pattern, line)]
        if matches:
            for key in current_ports or [None]:
                finding = {'severity': severity, 'title': title, 'port': key, 'source': report.name,
                           'evidence': matches[0][:350], 'impact': impact}
                findings.append(finding)
                if key is not None: rows[key]['issues'].append(title)
# Record actual requested scripts from commands.log where available.
for cmd in commands:
    m = re.search(r'(?:^|\s)-p\s+(\d+)(?:\s|$)', cmd)
    s = re.search(r'(?:^|\s)--script\s+(\S+)', cmd)
    if m and s and int(m.group(1)) in rows:
        rows[int(m.group(1))]['scripts'].update(x.removesuffix('.nse') for x in s.group(1).split(','))
# De-duplicate findings.
findings = list({(f['severity'], f['title'], f['port'], f['source']): f for f in findings}.values())
rank = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}
findings.sort(key=lambda f: (rank[f['severity']], f['port'] or 0))
counts = collections.Counter(f['severity'] for f in findings)
e = lambda v: html.escape(str(v), quote=True)
style = '''body{margin:0;background:#f4f6fa;color:#1c2638;font:15px system-ui,Arial,sans-serif}main{max-width:1200px;margin:30px auto;padding:0 20px}h1{margin-bottom:5px}h2{margin-top:32px}small,.muted{color:#64748b}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}.card,.panel{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:18px}.num{font-size:30px;font-weight:750}.panel{overflow:auto;margin:16px 0}table{border-collapse:collapse;width:100%;min-width:850px}th,td{padding:12px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}th{background:#f8fafc}code{font-size:12px;overflow-wrap:anywhere}.tag{border-radius:5px;padding:3px 8px;font-weight:650;font-size:12px;background:#e2e8f0}.High{background:#fee2e2;color:#991b1b}.Medium{background:#fef3c7;color:#92400e}.Info{background:#dbeafe;color:#1e40af}details{margin-top:5px}summary{cursor:pointer}footer{padding:24px 0;color:#64748b}'''
parts = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UDP Security Assessment</title><style>{style}</style></head><body><main>',
         '<h1>UDP Enumeration — Security Summary</h1>',
         f'<div class="muted">Source folder: {e(folder)} · Generated {e(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))}</div>',
         '<p><strong>Assessment note:</strong> Automated pattern matches are leads, not verified vulnerabilities. UDP <code>open|filtered</code> is inconclusive. Scripts listed are observed in output or recorded in <code>commands.log</code>.</p>',
         '<section class="cards">']
for label, value in [('UDP ports', len(rows)), ('High findings', counts['High']), ('Medium findings', counts['Medium']), ('Informational', counts['Info']), ('Reports read', len(reports))]:
    parts.append(f'<div class="card"><div class="num">{value}</div><div class="muted">{e(label)}</div></div>')
parts.append('</section><h2>Priority findings and potential impact</h2><div class="panel"><table><thead><tr><th>Priority</th><th>Port</th><th>Finding</th><th>Potential impact / next step</th><th>Evidence</th></tr></thead><tbody>')
for f in findings:
    parts.append(f'<tr><td><span class="tag {e(f["severity"])}">{e(f["severity"])}</span></td><td>{e(f["port"] if f["port"] is not None else "Unmapped")}/udp</td><td>{e(f["title"])}</td><td>{e(f["impact"])}</td><td><code>{e(f["evidence"])}</code><div class="muted">{e(f["source"])}</div></td></tr>')
if not findings: parts.append('<tr><td colspan="5">No configured finding patterns matched. Review the raw Nmap reports manually.</td></tr>')
parts.append('</tbody></table></div><h2>Port-by-port enumeration</h2><div class="panel"><table><thead><tr><th>Port</th><th>State</th><th>Service / version</th><th>NSE scripts seen or logged</th><th>Potential findings</th><th>Source reports</th></tr></thead><tbody>')
for port, r in sorted(rows.items()):
    scripts = ', '.join(sorted(r['scripts'])) or 'Not recorded / no output'
    issues = '; '.join(sorted(set(r['issues']))) or 'No matching indicators'
    parts.append(f'<tr><td><strong>{port}/udp</strong></td><td>{e(r["state"])}</td><td>{e(r["service"])}<div class="muted">{e(r["version"])}</div></td><td><code>{e(scripts)}</code></td><td>{e(issues)}</td><td>{e(", ".join(sorted(r["files"])))}</td></tr>')
if not rows: parts.append('<tr><td colspan="6">No UDP port lines found. Ensure these are Nmap normal-output (-oN) reports.</td></tr>')
parts.append('</tbody></table></div><h2>Executed commands</h2><div class="panel">')
if commands:
    for cmd in commands: parts.append(f'<details><summary>Command</summary><pre><code>{e(cmd)}</code></pre></details>')
else: parts.append('<p>No commands.log found; complete list of requested NSE scripts cannot be verified.</p>')
parts.append('</div><footer>Offline report generated from existing Nmap output. No additional scanning performed.</footer></main></body></html>')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text('\n'.join(parts), encoding='utf-8')
print(f'[+] Read {len(reports)} TXT reports; found {len(rows)} UDP ports and {len(findings)} potential findings.')
print(f'[+] HTML report: {output.resolve()}')
