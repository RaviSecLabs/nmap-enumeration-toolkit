#!/usr/bin/env python3
"""Generate a standalone HTML findings report from existing Nmap -oN .txt files.
Usage: python3 nmap_html_report.py /path/to/reports [-o report.html]
No external dependencies; never runs Nmap.
"""
import argparse
import collections
import datetime
import html
import pathlib
import re

RULES = [
    (r'Anonymous FTP login allowed|Anonymous login successful', 'High', 'Anonymous FTP access', 'Unauthenticated users may access FTP content.', 'Disable anonymous FTP unless explicitly required.'),
    (r'(?i)\bVULNERABLE\b|State:\s*VULNERABLE', 'High', 'NSE vulnerability indication', 'A vulnerability-check script reported a potentially exploitable issue; verify the script evidence.', 'Validate the finding and apply the relevant security fix.'),
    (r'(?i)message_signing:\s*disabled|message signing disabled|signing:\s*disabled', 'Medium', 'SMB signing disabled', 'Unsigned SMB traffic can be susceptible to relay or tampering in some environments.', 'Require SMB signing where supported.'),
    (r'(?i)\bSMBv1\b|\bNT LM 0\.12\b', 'Medium', 'Legacy SMB protocol', 'Legacy SMB versions increase exposure to known protocol weaknesses.', 'Disable SMBv1 where possible.'),
    (r'(?i)\bSSLv2\b|\bSSLv3\b|TLSv1\.0\b|TLSv1\.1\b', 'Medium', 'Obsolete TLS/SSL protocol', 'Outdated encryption protocols may expose communications to attacks.', 'Disable obsolete protocols and enable modern TLS.'),
    (r'(?i)http-methods:.*potentially risky methods|Potentially risky methods:', 'Medium', 'Potentially risky HTTP methods', 'HTTP methods may enable unexpected actions if permissions are misconfigured.', 'Review allowed methods and access controls.'),
    (r'(?i)\bguest access\b|\banonymous access\b|\bguest ok\b', 'Medium', 'Possible guest access', 'Guest access may expose resources without individual authentication.', 'Review anonymous and guest permissions.'),
    (r'(?i)\bweak cipher\b|\b3DES\b|\bRC4\b', 'Medium', 'Weak cryptography indicator', 'Weak cipher support may reduce confidentiality.', 'Disable weak ciphers after compatibility review.'),
    (r'(?i)\bworld[- ]writable\b|\bwriteable\b|\bwritable\b', 'Medium', 'Potential writable resource', 'Write permissions may permit unauthorised changes depending on access controls.', 'Confirm permissions and restrict write access.'),
    (r'(?i)\bCVE-\d{4}-\d+\b', 'Info', 'CVE reference in scan output', 'A CVE was mentioned, but the reference alone does not prove vulnerability.', 'Review the related script output and verify applicability.'),
]
SEVERITY = {'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
PORT_HINTS = {21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'domain',80:'http',111:'rpcbind',139:'netbios-ssn',443:'https',445:'microsoft-ds',2049:'nfs',3306:'mysql',5432:'postgresql',5900:'vnc',8080:'http-proxy'}


def esc(value):
    return html.escape(str(value), quote=True)


def parse_report(path):
    text = path.read_text(encoding='utf-8', errors='replace')
    ports = {}
    for line in text.splitlines():
        m = re.match(r'^\s*(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)(?:\s+(.*))?$', line)
        if m:
            port, proto, state, service, version = m.groups()
            ports[(int(port), proto)] = {'port':int(port), 'proto':proto, 'state':state, 'service':service, 'version':(version or '').strip()}
    filename_match = re.search(r'(\d{2,5})(?:\.txt)$', path.name)
    if not ports and filename_match:
        port = int(filename_match.group(1))
        ports[(port, 'tcp')] = {'port':port,'proto':'tcp','state':'unknown','service':PORT_HINTS.get(port,'unknown'),'version':''}
    script_names = sorted(set(re.findall(r'^\s*\|_?\s*([A-Za-z0-9][A-Za-z0-9_-]*):', text, flags=re.M)))
    # Some NSE scripts output a top-level line with '| script-name:'; not all do.
    findings = []
    for pattern, severity, title, impact, remediation in RULES:
        matches = []
        for line in text.splitlines():
            if re.search(pattern, line):
                matches.append(line.strip()[:300])
            if len(matches) >= 3:
                break
        if matches:
            findings.append({'severity':severity,'title':title,'impact':impact,'remediation':remediation,'evidence':matches,'source':path.name})
    # Port-specific protocol observation: service identification is not a proven vulnerability.
    for port in ports.values():
        if port['port'] == 23 and port['state'].startswith('open'):
            findings.append({'severity':'Medium','title':'Telnet service exposed','impact':'Telnet typically transmits authentication data without encryption.','remediation':'Replace Telnet with SSH or isolate access.','evidence':[f"{port['port']}/{port['proto']} {port['state']} {port['service']}"],'source':path.name})
    return {'path':path, 'ports':list(ports.values()), 'scripts':script_names, 'findings':findings, 'text':text}


def generate(reports, source_dir):
    # Merge evidence from per-port files. An individual report can contain multiple ports.
    port_rows = {}
    all_findings = []
    for report in reports:
        for p in report['ports']:
            key = (p['port'], p['proto'])
            row = port_rows.setdefault(key, {**p,'scripts':set(),'files':set(),'findings':[]})
            if row['service'] in ('unknown','tcp') and p['service'] not in ('unknown','tcp'):
                row['service'] = p['service']
            if not row['version'] and p['version']:
                row['version'] = p['version']
            row['scripts'].update(report['scripts'])
            row['files'].add(report['path'].name)
            for f in report['findings']:
                # Findings are associated with all ports in a multiport file; mark as such.
                item = dict(f)
                item['port'] = f"{p['port']}/{p['proto']}"
                item['multiport'] = len(report['ports']) > 1
                row['findings'].append(item)
                all_findings.append(item)
        if not report['ports']:
            for f in report['findings']:
                all_findings.append({**f, 'port':'Not identified', 'multiport':False})
    # De-duplicate by finding, port, and source.
    unique = {}
    for f in all_findings:
        unique[(f['port'], f['title'], f['source'])] = f
    all_findings = sorted(unique.values(), key=lambda f:(-SEVERITY[f['severity']], f['port'], f['title']))
    counts = collections.Counter(f['severity'] for f in all_findings)
    rows_html = []
    for (port, proto), row in sorted(port_rows.items()):
        titles = sorted(set(f['title'] for f in row['findings']))
        severity = max((f['severity'] for f in row['findings']), key=lambda x:SEVERITY[x], default='Info')
        scripts = ', '.join(sorted(row['scripts'])) if row['scripts'] else 'No script output identified'
        rows_html.append(f'<tr><td><strong>{port}/{esc(proto)}</strong></td><td>{esc(row["service"])}</td><td>{esc(row["version"] or "Not identified")}</td><td>{esc(scripts)}<div class="muted">Observed output only; full invocation unknown</div></td><td>{esc("; ".join(titles) if titles else "No rule-based issue detected")}</td><td><span class="pill {esc(severity.lower())}">{esc(severity)}</span></td><td>{esc(", ".join(sorted(row["files"])))}</td></tr>')
    findings_html = []
    for f in all_findings:
        evidence = ''.join(f'<li><code>{esc(line)}</code></li>' for line in f['evidence'])
        association = ' (multi-port file: attribution requires review)' if f.get('multiport') else ''
        findings_html.append(f'<article class="finding"><div class="finding-head"><span class="pill {esc(f["severity"].lower())}">{esc(f["severity"])}</span><strong>{esc(f["title"])}</strong><span class="muted">{esc(f["port"])} · {esc(f["source"])}{esc(association)}</span></div><p><b>Potential impact:</b> {esc(f["impact"])}</p><p><b>Recommended action:</b> {esc(f["remediation"])}</p><details><summary>Supporting scan evidence</summary><ul>{evidence}</ul></details></article>')
    if not findings_html:
        findings_html.append('<p>No findings matched the built-in rules. This does not mean the target is secure.</p>')
    timestamp = datetime.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nmap Enumeration Security Summary</title>
<style>
:root{{--bg:#f5f7fb;--ink:#172033;--muted:#607087;--line:#e1e7f0;--navy:#182c4d}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}header{{background:var(--navy);color:white;padding:38px max(24px,calc((100vw - 1160px)/2))}}header h1{{margin:0;font-size:30px}}header p{{opacity:.85;margin:8px 0 0}}main{{max-width:1200px;margin:auto;padding:24px}}h2{{margin:30px 0 14px;font-size:21px}}.cards{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}}.card,.panel,.finding{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px}}.card .value{{font-size:29px;font-weight:750}}.muted{{color:var(--muted);font-size:12px}}.card .muted{{font-size:13px}}.pill{{display:inline-block;border-radius:100px;padding:3px 10px;font-size:12px;font-weight:700;background:#e8edf4;color:#40506a}}.pill.high{{background:#ffe4e6;color:#aa1835}}.pill.medium{{background:#fff0d7;color:#945400}}.pill.low{{background:#e1efff;color:#2053a5}}.pill.info{{background:#e6edf2;color:#4b5e73}}.finding{{margin-bottom:12px}}.finding-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}.finding p{{margin:10px 0}}details{{margin-top:8px}}summary{{cursor:pointer;color:#245da0;font-weight:600}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}.table-wrap{{overflow-x:auto;background:white;border:1px solid var(--line);border-radius:12px}}table{{width:100%;border-collapse:collapse;min-width:1050px}}th,td{{text-align:left;padding:13px;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#edf2f9;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}td{{font-size:13px}}tr:last-child td{{border-bottom:0}}.notice{{border-left:4px solid #4b73ad;background:#edf4ff;padding:14px 18px;border-radius:6px}}@media(max-width:760px){{.cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}header h1{{font-size:24px}}}}@media print{{body{{background:white}}header{{padding:18px 0;color:black;background:white}}main{{padding:0}}details{{display:block}}}}
</style></head><body><header><h1>Nmap Enumeration — Security Assessment Summary</h1><p>Source: {esc(source_dir)} · Generated: {esc(timestamp)}</p></header><main>
<div class="notice"><b>Assessment status: Preliminary.</b> Findings are inferred from saved Nmap output using explicit rules. They are not confirmed compromise paths or proof of exploitability. Script names are those visible in NSE output, not necessarily every script requested.</div>
<h2>Executive summary</h2><section class="cards"><div class="card"><div class="value">{len(port_rows)}</div><div class="muted">Distinct reported ports</div></div><div class="card"><div class="value">{counts['High']}</div><div class="muted">High findings</div></div><div class="card"><div class="value">{counts['Medium']}</div><div class="muted">Medium findings</div></div><div class="card"><div class="value">{counts['Low']}</div><div class="muted">Low findings</div></div><div class="card"><div class="value">{counts['Info']}</div><div class="muted">Informational findings</div></div></section>
<h2>Priority findings and potential impact</h2>{''.join(findings_html)}
<h2>Port-by-port findings and NSE script output</h2><div class="table-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>NSE scripts observed</th><th>Key findings</th><th>Priority</th><th>Source report</th></tr></thead><tbody>{''.join(rows_html) if rows_html else '<tr><td colspan="7">No open-port records found in the supplied reports.</td></tr>'}</tbody></table></div>
<h2>Interpretation and limitations</h2><div class="panel"><p><b>Script tracking:</b> Nmap normal output may show only scripts that produced visible results. To report all invoked scripts accurately, save the full Nmap command or a separate manifest during scanning.</p><p><b>Evidence:</b> A keyword match is a lead for manual review. A CVE mention, service version, or open port alone does not establish exploitability. Multi-port files may require manual attribution of findings.</p><p><b>Coverage:</b> This report uses the supplied text files only; it does not perform additional scanning, CVE lookups, or validation. Some issues will not be detected by the built-in rules.</p><p><b>Suggested next step:</b> Verify the most important findings in your authorised lab and document confirmed impact and remediation.</p></div>
</main></body></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=pathlib.Path, help='Folder containing Nmap .txt reports')
    parser.add_argument('-o','--output',type=pathlib.Path,help='Output HTML path (default: FOLDER/security_summary.html)')
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error(f'Not a directory: {args.folder}')
    output = args.output or (args.folder / 'security_summary.html')
    paths = sorted(p for p in args.folder.glob('*.txt') if p.is_file() and p.name not in {'security_findings.txt'})
    if not paths:
        parser.error('No .txt files found in folder')
    reports = [parse_report(p) for p in paths]
    output.write_text(generate(reports, args.folder), encoding='utf-8')
    print(f'[+] Analysed {len(reports)} text reports')
    print(f'[+] HTML report: {output.resolve()}')

if __name__ == '__main__':
    main()
