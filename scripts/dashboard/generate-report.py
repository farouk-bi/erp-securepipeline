#!/usr/bin/env python3
"""
ERP SecurePipeline — Dashboard Sécurité v3 (Premium)
Génère un dashboard HTML professionnel à partir des rapports de scan.
"""

import json
import os
import sys
from datetime import datetime


def load_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def parse_trivy(report):
    stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulns': []}
    for result in report.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            sev = vuln.get('Severity', 'UNKNOWN').lower()
            if sev in stats:
                stats[sev] += 1
            stats['vulns'].append({
                'id': vuln.get('VulnerabilityID', 'N/A'),
                'pkg': vuln.get('PkgName', 'N/A'),
                'installed': vuln.get('InstalledVersion', 'N/A'),
                'fixed': vuln.get('FixedVersion', 'N/A'),
                'severity': vuln.get('Severity', 'N/A'),
                'title': (vuln.get('Title', '') or vuln.get('Description', 'N/A'))[:120]
            })
    return stats


def parse_gitleaks(report):
    if isinstance(report, list):
        return len(report)
    return 0


def parse_zap(report):
    alerts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'details': []}
    for site in report.get('site', []):
        for alert in site.get('alerts', []):
            risk = alert.get('riskdesc', '').split(' ')[0].lower()
            if risk in alerts:
                alerts[risk] += 1
            alerts['details'].append({
                'name': alert.get('name', 'N/A'),
                'risk': alert.get('riskdesc', 'N/A'),
                'count': len(alert.get('instances', [])),
                'solution': (alert.get('solution', '') or '')[:150]
            })
    return alerts


def parse_sbom(report):
    components = report.get('components', [])
    return {
        'total': len(components),
        'libraries': len([c for c in components if c.get('type') == 'library']),
        'frameworks': len([c for c in components if c.get('type') == 'framework']),
    }


def parse_iac(report):
    stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'misconfigs': []}
    for result in report.get('Results', []):
        for mc in result.get('Misconfigurations', []):
            sev = mc.get('Severity', 'UNKNOWN').lower()
            if sev in stats:
                stats[sev] += 1
            stats['misconfigs'].append({
                'id': mc.get('ID', 'N/A'),
                'title': mc.get('Title', 'N/A'),
                'severity': mc.get('Severity', 'N/A'),
                'file': result.get('Target', 'N/A'),
                'resolution': (mc.get('Resolution', '') or '')[:120]
            })
    return stats


def calc_score(tc, th, tm, secrets, zap_h):
    s = 100 - (tc * 25) - (th * 10) - (tm * 3) - (secrets * 30) - (zap_h * 15)
    return max(0, min(100, s))


def generate_html(reports_dir, build_number, output_file):
    # Load reports
    trivy_sca = parse_trivy(load_json(f'{reports_dir}/trivy-sca.json'))
    trivy_image = parse_trivy(load_json(f'{reports_dir}/trivy-image.json'))
    gitleaks_count = parse_gitleaks(load_json(f'{reports_dir}/gitleaks.json'))
    zap = parse_zap(load_json(f'{reports_dir}/zap-report.json'))
    sbom = parse_sbom(load_json(f'{reports_dir}/sbom.json'))
    iac = parse_iac(load_json(f'{reports_dir}/trivy-iac.json'))
    g1 = load_json(f'{reports_dir}/security-gate-1.json')
    g2 = load_json(f'{reports_dir}/security-gate-2.json')

    g1p = g1.get('gate_passed', g1.get('passed', False))
    g2p = g2.get('gate_passed', g2.get('passed', False))

    tc = trivy_sca['critical'] + trivy_image['critical']
    th = trivy_sca['high'] + trivy_image['high'] + zap['high']
    tm = trivy_sca['medium'] + trivy_image['medium'] + zap['medium']
    tl = trivy_sca['low'] + trivy_image['low'] + zap['low']
    ta = tc + th + tm + tl
    iac_total = iac['critical'] + iac['high'] + iac['medium'] + iac['low']

    score = calc_score(tc, th, tm, gitleaks_count, zap['high'])

    if score >= 90:
        sc, sl, sg = '#10b981', 'EXCELLENT', 'rgba(16,185,129,0.15)'
    elif score >= 70:
        sc, sl, sg = '#f59e0b', 'ACCEPTABLE', 'rgba(245,158,11,0.15)'
    elif score >= 40:
        sc, sl, sg = '#f97316', 'FAIBLE', 'rgba(249,115,22,0.15)'
    else:
        sc, sl, sg = '#ef4444', 'CRITIQUE', 'rgba(239,68,68,0.15)'

    circ = 2 * 3.14159 * 58
    offset = circ * (1 - score / 100)
    ts = datetime.now().strftime('%d/%m/%Y à %H:%M')

    # Bar widths
    bt = max(ta, 1)

    # Vuln tables
    def vuln_rows(vulns, limit=10):
        if not vulns:
            return '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem;">Aucune vulnérabilité détectée ✅</td></tr>'
        return ''.join(f'''<tr>
            <td><code>{v['id']}</code></td>
            <td><strong>{v['pkg']}</strong></td>
            <td>{v['installed']}</td>
            <td>{v['fixed'] if v['fixed'] != 'N/A' else '<span style="color:var(--muted)">—</span>'}</td>
            <td><span class="sev sev-{v['severity'].lower()}">{v['severity']}</span></td>
            <td class="truncate">{v['title']}</td>
        </tr>''' for v in vulns[:limit])

    def iac_rows():
        if not iac['misconfigs']:
            return '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem;">Aucune misconfiguration détectée ✅</td></tr>'
        return ''.join(f'''<tr>
            <td><code>{m['id']}</code></td>
            <td>{m['title']}</td>
            <td><span class="mono">{m['file']}</span></td>
            <td><span class="sev sev-{m['severity'].lower()}">{m['severity']}</span></td>
            <td class="truncate">{m['resolution']}</td>
        </tr>''' for m in iac['misconfigs'][:10])

    def zap_rows():
        if not zap['details']:
            return '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:2rem;">Aucune alerte DAST détectée ✅</td></tr>'
        return ''.join(f'''<tr>
            <td>{a['name']}</td>
            <td><span class="sev sev-{a['risk'].split(' ')[0].lower() if a['risk'] != 'N/A' else 'info'}">{a['risk']}</span></td>
            <td style="text-align:center">{a['count']}</td>
            <td class="truncate">{a['solution']}</td>
        </tr>''' for a in zap['details'][:10])

    # Pipeline stages
    stages = [
        ('Checkout', '📥', True),
        ('Build', '🔨', True),
        ('Tests', '🧪', True),
        ('Docker', '🐳', True),
        ('SAST', '🔍', True),
        ('SCA', '📦', True),
        ('Secrets', '🔑', True),
        ('Container', '🛡️', True),
        ('Gate #1', '🚦', g1p),
        ('Staging', '🚀', True),
        ('DAST', '🌐', True),
        ('Gate #2', '🚦', g2p if g2 else True),
    ]

    pipeline_html = ''
    for i, (name, icon, passed) in enumerate(stages):
        cls = 'pass' if passed else 'fail'
        pipeline_html += f'<div class="pip-stage pip-{cls}"><div class="pip-icon">{icon}</div><div class="pip-name">{name}</div><div class="pip-status">{"✓" if passed else "✗"}</div></div>'
        if i < len(stages) - 1:
            pipeline_html += '<div class="pip-line"></div>'

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Dashboard — Build #{build_number} | ERP SecurePipeline</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #050816;
    --bg2: #0c1222;
    --surface: #111a2e;
    --surface2: #162034;
    --border: rgba(99,115,155,0.2);
    --border-h: rgba(99,115,155,0.4);
    --text: #e1e7ef;
    --text2: #c1c9d6;
    --muted: #6b7a99;
    --green: #10b981;
    --green-bg: rgba(16,185,129,0.1);
    --red: #ef4444;
    --red-bg: rgba(239,68,68,0.1);
    --orange: #f97316;
    --orange-bg: rgba(249,115,22,0.1);
    --yellow: #eab308;
    --yellow-bg: rgba(234,179,8,0.1);
    --blue: #3b82f6;
    --blue-bg: rgba(59,130,246,0.1);
    --cyan: #06b6d4;
    --purple: #8b5cf6;
    --radius: 14px;
}}

/* ─── RESET & BASE ─── */
*{{ margin:0; padding:0; box-sizing:border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
}}

/* ─── ANIMATIONS ─── */
@keyframes fadeUp {{
    from {{ opacity:0; transform:translateY(30px); }}
    to {{ opacity:1; transform:translateY(0); }}
}}
@keyframes scoreReveal {{
    from {{ stroke-dashoffset: {circ}; }}
    to {{ stroke-dashoffset: {offset}; }}
}}
@keyframes pulse {{
    0%,100% {{ opacity:1; }} 50% {{ opacity:0.6; }}
}}
@keyframes shimmer {{
    0% {{ background-position: -200% center; }}
    100% {{ background-position: 200% center; }}
}}

.anim {{ animation: fadeUp 0.7s ease-out both; }}
.d1 {{ animation-delay: 0.05s; }}
.d2 {{ animation-delay: 0.1s; }}
.d3 {{ animation-delay: 0.15s; }}
.d4 {{ animation-delay: 0.2s; }}
.d5 {{ animation-delay: 0.25s; }}
.d6 {{ animation-delay: 0.3s; }}
.d7 {{ animation-delay: 0.35s; }}
.d8 {{ animation-delay: 0.4s; }}

/* ─── LAYOUT ─── */
.wrap {{ max-width: 1320px; margin: 0 auto; padding: 2rem 1.5rem; }}

/* ─── HEADER ─── */
.hdr {{
    text-align: center;
    padding: 3rem 2rem;
    margin-bottom: 2rem;
    border-radius: var(--radius);
    background: linear-gradient(135deg, rgba(59,130,246,0.08) 0%, rgba(139,92,246,0.08) 50%, rgba(6,182,212,0.08) 100%);
    border: 1px solid var(--border);
    position: relative;
    overflow: hidden;
}}
.hdr::before {{
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle at 30% 50%, rgba(59,130,246,0.04) 0%, transparent 50%),
                radial-gradient(circle at 70% 50%, rgba(139,92,246,0.04) 0%, transparent 50%);
    pointer-events: none;
}}
.hdr h1 {{
    font-size: 1.75rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #60a5fa, #a78bfa, #67e8f9);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.75rem;
    position: relative;
}}
.hdr-meta {{
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    flex-wrap: wrap;
    position: relative;
}}
.hdr-tag {{
    padding: 0.3rem 0.9rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    font-size: 0.78rem;
    color: var(--text2);
    font-weight: 500;
}}

/* ─── CARDS GRID ─── */
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.25rem;
    margin-bottom: 2.5rem;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.5rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
}}
.card::after {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: transparent;
    transition: background 0.3s;
}}
.card:hover {{
    border-color: var(--border-h);
    transform: translateY(-3px);
    box-shadow: 0 8px 30px rgba(0,0,0,0.3);
}}
.card:hover::after {{ background: linear-gradient(90deg, var(--blue), var(--purple)); }}
.card-label {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    margin-bottom: 0.75rem;
}}
.card-val {{
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -1px;
}}
.card-sub {{
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 0.4rem;
    font-weight: 400;
}}

/* ─── SCORE HERO ─── */
.score-hero {{
    grid-column: span 2;
    display: flex;
    align-items: center;
    gap: 2.5rem;
    padding: 2rem;
}}
.score-ring {{ position: relative; flex-shrink: 0; }}
.score-ring svg {{ filter: drop-shadow(0 0 20px {sg}); }}
.score-ring .bg {{ fill: none; stroke: var(--surface2); stroke-width: 6; }}
.score-ring .arc {{
    fill: none;
    stroke: url(#scoreGrad);
    stroke-width: 7;
    stroke-linecap: round;
    stroke-dasharray: {circ};
    stroke-dashoffset: {offset};
    transform: rotate(-90deg);
    transform-origin: center;
    animation: scoreReveal 2s cubic-bezier(0.4, 0, 0.2, 1) 0.5s both;
}}
.score-num {{
    font-size: 2.8rem;
    font-weight: 900;
    fill: {sc};
    letter-spacing: -2px;
}}
.score-of {{ font-size: 0.75rem; fill: var(--muted); font-weight: 500; }}
.score-detail h3 {{
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    font-weight: 600;
    margin-bottom: 0.25rem;
}}
.score-grade {{
    font-size: 1.8rem;
    font-weight: 800;
    color: {sc};
    letter-spacing: -0.5px;
}}
.score-desc {{
    color: var(--muted);
    font-size: 0.82rem;
    margin: 0.5rem 0 1rem;
}}
.gates {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
.gate {{
    padding: 0.3rem 0.75rem;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.3px;
}}
.gate-pass {{ background: var(--green-bg); color: var(--green); border: 1px solid rgba(16,185,129,0.25); }}
.gate-fail {{ background: var(--red-bg); color: var(--red); border: 1px solid rgba(239,68,68,0.25); }}

/* ─── SECTIONS ─── */
.sec {{ margin-bottom: 2.5rem; }}
.sec-title {{
    font-size: 1.15rem;
    font-weight: 700;
    margin-bottom: 1.25rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 0.6rem;
}}
.sec-title .icon {{
    font-size: 1.3rem;
}}

/* ─── DISTRIBUTION BAR ─── */
.dist-card {{ padding: 1.75rem; }}
.dist-bar {{
    height: 10px;
    display: flex;
    border-radius: 5px;
    overflow: hidden;
    background: var(--surface2);
    margin-bottom: 1.25rem;
}}
.dist-bar div {{ min-width: 2px; transition: width 1.5s ease; }}
.dist-labels {{
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
}}
.dist-item {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    color: var(--text2);
}}
.dist-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.dist-count {{
    font-weight: 700;
    color: var(--text);
}}

/* ─── SCANNERS TABLE ─── */
.scan-grid {{ display: grid; gap: 0.5rem; }}
.scan-row {{
    display: grid;
    grid-template-columns: 1.5fr repeat(4, 1fr) 1.2fr;
    gap: 1rem;
    padding: 1rem 1.25rem;
    border-radius: 10px;
    align-items: center;
    font-size: 0.85rem;
    transition: all 0.2s;
}}
.scan-row:not(.scan-hdr) {{
    background: var(--surface);
    border: 1px solid var(--border);
}}
.scan-row:not(.scan-hdr):hover {{
    border-color: var(--border-h);
    background: var(--surface2);
}}
.scan-hdr {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    padding: 0.5rem 1.25rem;
}}
.scan-name {{ font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }}
.scan-icon {{ font-size: 1.1rem; }}
.scan-val {{ font-weight: 600; font-variant-numeric: tabular-nums; }}

/* ─── SEVERITY BADGES ─── */
.sev {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}
.sev-critical {{ background: var(--red-bg); color: var(--red); }}
.sev-high {{ background: var(--orange-bg); color: var(--orange); }}
.sev-medium {{ background: var(--yellow-bg); color: var(--yellow); }}
.sev-low {{ background: var(--blue-bg); color: var(--blue); }}
.sev-info {{ background: rgba(6,182,212,0.1); color: var(--cyan); }}

.status {{
    padding: 0.25rem 0.7rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
}}
.st-pass {{ background: var(--green-bg); color: var(--green); }}
.st-fail {{ background: var(--red-bg); color: var(--red); }}

/* ─── PIPELINE ─── */
.pip-wrap {{
    display: flex;
    align-items: center;
    gap: 0;
    overflow-x: auto;
    padding: 1.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
}}
.pip-stage {{
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.3rem;
    padding: 0.75rem 0.6rem;
    border-radius: 10px;
    min-width: 75px;
    text-align: center;
    flex-shrink: 0;
    transition: all 0.2s;
}}
.pip-stage:hover {{ transform: scale(1.05); }}
.pip-pass {{
    background: var(--green-bg);
    border: 1px solid rgba(16,185,129,0.2);
}}
.pip-fail {{
    background: var(--red-bg);
    border: 1px solid rgba(239,68,68,0.2);
}}
.pip-icon {{ font-size: 1.1rem; }}
.pip-name {{ font-size: 0.65rem; font-weight: 600; color: var(--text2); line-height: 1.2; }}
.pip-status {{
    font-size: 0.65rem;
    font-weight: 800;
}}
.pip-pass .pip-status {{ color: var(--green); }}
.pip-fail .pip-status {{ color: var(--red); }}
.pip-line {{
    width: 20px;
    height: 2px;
    background: var(--border);
    flex-shrink: 0;
}}

/* ─── DATA TABLES ─── */
.tbl-wrap {{
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}}
table {{ width: 100%; border-collapse: collapse; }}
th {{
    text-align: left;
    padding: 0.85rem 1.1rem;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
}}
td {{
    padding: 0.75rem 1.1rem;
    font-size: 0.82rem;
    border-bottom: 1px solid rgba(99,115,155,0.1);
    color: var(--text2);
}}
tr:hover td {{ background: rgba(59,130,246,0.03); }}
code {{
    background: rgba(59,130,246,0.08);
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    font-size: 0.78rem;
    color: var(--cyan);
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
}}
.mono {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.78rem; color: var(--muted); }}
.truncate {{ max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

/* ─── FOOTER ─── */
.ftr {{
    text-align: center;
    padding: 2.5rem 2rem;
    margin-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.78rem;
}}
.ftr-tools {{
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    margin: 1rem 0;
    flex-wrap: wrap;
}}
.ftr-tool {{
    padding: 0.3rem 0.8rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    font-size: 0.72rem;
    color: var(--text2);
    transition: all 0.2s;
}}
.ftr-tool:hover {{ border-color: var(--blue); color: var(--blue); }}

/* ─── RESPONSIVE ─── */
@media (max-width: 768px) {{
    .score-hero {{ grid-column: span 1; flex-direction: column; text-align: center; }}
    .scan-row:not(.scan-hdr) {{ grid-template-columns: 1fr 1fr; }}
    .scan-hdr {{ display: none; }}
    .grid {{ grid-template-columns: 1fr 1fr; }}
    .hdr h1 {{ font-size: 1.3rem; }}
}}
@media (max-width: 480px) {{
    .grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="wrap">

    <!-- HEADER -->
    <div class="hdr anim">
        <h1>🛡️ ERP SecurePipeline — Security Dashboard</h1>
        <div class="hdr-meta">
            <span class="hdr-tag">🔨 Build #{build_number}</span>
            <span class="hdr-tag">📅 {ts}</span>
            <span class="hdr-tag">📦 {sbom['total']} composants</span>
            <span class="hdr-tag">{'🟢 SECURE' if score >= 70 else '🔴 AT RISK'}</span>
        </div>
    </div>

    <!-- SCORE + METRICS -->
    <div class="grid">
        <div class="card score-hero anim d1">
            <div class="score-ring">
                <svg width="150" height="150" viewBox="0 0 130 130">
                    <defs>
                        <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="{sc}"/>
                            <stop offset="100%" stop-color="{'#06b6d4' if score >= 70 else '#f97316'}"/>
                        </linearGradient>
                    </defs>
                    <circle class="bg" cx="65" cy="65" r="58"/>
                    <circle class="arc" cx="65" cy="65" r="58"/>
                    <text class="score-num" x="65" y="62" text-anchor="middle" dominant-baseline="middle">{score}</text>
                    <text class="score-of" x="65" y="82" text-anchor="middle">/100</text>
                </svg>
            </div>
            <div class="score-detail">
                <h3>Score Sécurité Global</h3>
                <div class="score-grade">{sl}</div>
                <div class="score-desc">Analyse combinée SAST + SCA + Container + DAST + Secrets + IaC</div>
                <div class="gates">
                    <span class="gate {'gate-pass' if g1p else 'gate-fail'}">🚦 Gate #1 {'PASSED' if g1p else 'FAILED'}</span>
                    <span class="gate {'gate-pass' if g2p else 'gate-fail'}">🚦 Gate #2 {'PASSED' if g2p else 'FAILED'}</span>
                </div>
            </div>
        </div>

        <div class="card anim d2">
            <div class="card-label">🔴 Critiques</div>
            <div class="card-val" style="color:var(--red)">{tc}</div>
            <div class="card-sub">Vulnérabilités critiques</div>
        </div>
        <div class="card anim d3">
            <div class="card-label">🟠 Élevées</div>
            <div class="card-val" style="color:var(--orange)">{th}</div>
            <div class="card-sub">Vulnérabilités high</div>
        </div>
        <div class="card anim d4">
            <div class="card-label">🟡 Moyennes</div>
            <div class="card-val" style="color:var(--yellow)">{tm}</div>
            <div class="card-sub">Vulnérabilités medium</div>
        </div>
        <div class="card anim d5">
            <div class="card-label">🔵 Faibles</div>
            <div class="card-val" style="color:var(--blue)">{tl}</div>
            <div class="card-sub">Vulnérabilités low</div>
        </div>
        <div class="card anim d6">
            <div class="card-label">🔑 Secrets</div>
            <div class="card-val" style="color:{'var(--red)' if gitleaks_count > 0 else 'var(--green)'}">{gitleaks_count}</div>
            <div class="card-sub">Détectés par GitLeaks</div>
        </div>
        <div class="card anim d7">
            <div class="card-label">📦 SBOM</div>
            <div class="card-val" style="color:var(--cyan)">{sbom['total']}</div>
            <div class="card-sub">{sbom['libraries']} librairies</div>
        </div>
        <div class="card anim d8">
            <div class="card-label">🏗️ IaC</div>
            <div class="card-val" style="color:{'var(--orange)' if iac_total > 0 else 'var(--green)'}">{iac_total}</div>
            <div class="card-sub">Misconfigurations K8s</div>
        </div>
    </div>

    <!-- DISTRIBUTION -->
    <div class="sec anim d3">
        <div class="sec-title"><span class="icon">📊</span> Répartition des Vulnérabilités</div>
        <div class="card dist-card">
            <div class="dist-bar">
                <div style="width:{(tc/bt)*100:.1f}%;background:var(--red)"></div>
                <div style="width:{(th/bt)*100:.1f}%;background:var(--orange)"></div>
                <div style="width:{(tm/bt)*100:.1f}%;background:var(--yellow)"></div>
                <div style="width:{(tl/bt)*100:.1f}%;background:var(--blue)"></div>
            </div>
            <div class="dist-labels">
                <div class="dist-item"><span class="dist-dot" style="background:var(--red)"></span>Critical <span class="dist-count">{tc}</span></div>
                <div class="dist-item"><span class="dist-dot" style="background:var(--orange)"></span>High <span class="dist-count">{th}</span></div>
                <div class="dist-item"><span class="dist-dot" style="background:var(--yellow)"></span>Medium <span class="dist-count">{tm}</span></div>
                <div class="dist-item"><span class="dist-dot" style="background:var(--blue)"></span>Low <span class="dist-count">{tl}</span></div>
                <div class="dist-item" style="margin-left:auto;font-weight:700;color:var(--text)">Total: {ta}</div>
            </div>
        </div>
    </div>

    <!-- SCANNERS -->
    <div class="sec anim d4">
        <div class="sec-title"><span class="icon">🔍</span> Résultats par Scanner</div>
        <div class="scan-grid">
            <div class="scan-row scan-hdr">
                <div>Scanner</div><div>Critical</div><div>High</div><div>Medium</div><div>Low</div><div>Status</div>
            </div>
            <div class="scan-row">
                <div class="scan-name"><span class="scan-icon">📦</span> Trivy SCA</div>
                <div class="scan-val">{trivy_sca['critical']}</div><div class="scan-val">{trivy_sca['high']}</div>
                <div class="scan-val">{trivy_sca['medium']}</div><div class="scan-val">{trivy_sca['low']}</div>
                <div><span class="status {'st-pass' if trivy_sca['critical']==0 and trivy_sca['high']==0 else 'st-fail'}">{'✓ Clean' if trivy_sca['critical']==0 and trivy_sca['high']==0 else '✗ Issues'}</span></div>
            </div>
            <div class="scan-row">
                <div class="scan-name"><span class="scan-icon">🐳</span> Trivy Image</div>
                <div class="scan-val">{trivy_image['critical']}</div><div class="scan-val">{trivy_image['high']}</div>
                <div class="scan-val">{trivy_image['medium']}</div><div class="scan-val">{trivy_image['low']}</div>
                <div><span class="status {'st-pass' if trivy_image['critical']==0 and trivy_image['high']==0 else 'st-fail'}">{'✓ Clean' if trivy_image['critical']==0 and trivy_image['high']==0 else '✗ Issues'}</span></div>
            </div>
            <div class="scan-row">
                <div class="scan-name"><span class="scan-icon">🔑</span> GitLeaks</div>
                <div class="scan-val">—</div><div class="scan-val">—</div>
                <div class="scan-val">—</div><div class="scan-val">—</div>
                <div><span class="status {'st-pass' if gitleaks_count==0 else 'st-fail'}">{gitleaks_count} secret(s)</span></div>
            </div>
            <div class="scan-row">
                <div class="scan-name"><span class="scan-icon">🌐</span> OWASP ZAP</div>
                <div class="scan-val">—</div><div class="scan-val">{zap['high']}</div>
                <div class="scan-val">{zap['medium']}</div><div class="scan-val">{zap['low']}</div>
                <div><span class="status {'st-pass' if zap['high']==0 else 'st-fail'}">{'✓ Clean' if zap['high']==0 else '✗ Issues'}</span></div>
            </div>
            <div class="scan-row">
                <div class="scan-name"><span class="scan-icon">🏗️</span> Trivy IaC</div>
                <div class="scan-val">{iac['critical']}</div><div class="scan-val">{iac['high']}</div>
                <div class="scan-val">{iac['medium']}</div><div class="scan-val">{iac['low']}</div>
                <div><span class="status {'st-pass' if iac['critical']==0 and iac['high']==0 else 'st-fail'}">{'✓ Clean' if iac['critical']==0 and iac['high']==0 else '✗ Issues'}</span></div>
            </div>
        </div>
    </div>

    <!-- PIPELINE -->
    <div class="sec anim d5">
        <div class="sec-title"><span class="icon">🔄</span> Pipeline CI/CD — Stages</div>
        <div class="pip-wrap">
            {pipeline_html}
        </div>
    </div>

    <!-- SCA DETAILS -->
    <div class="sec anim d6">
        <div class="sec-title"><span class="icon">📦</span> Vulnérabilités Dépendances (SCA)</div>
        <div class="tbl-wrap">
            <table>
                <tr><th>CVE</th><th>Package</th><th>Installée</th><th>Corrigée</th><th>Sévérité</th><th>Description</th></tr>
                {vuln_rows(trivy_sca['vulns'])}
            </table>
        </div>
    </div>

    <!-- IMAGE DETAILS -->
    <div class="sec anim d7">
        <div class="sec-title"><span class="icon">🐳</span> Vulnérabilités Image Docker</div>
        <div class="tbl-wrap">
            <table>
                <tr><th>CVE</th><th>Package</th><th>Installée</th><th>Corrigée</th><th>Sévérité</th><th>Description</th></tr>
                {vuln_rows(trivy_image['vulns'])}
            </table>
        </div>
    </div>

    <!-- ZAP DETAILS -->
    <div class="sec anim d8">
        <div class="sec-title"><span class="icon">🌐</span> Alertes OWASP ZAP (DAST)</div>
        <div class="tbl-wrap">
            <table>
                <tr><th>Alerte</th><th>Risque</th><th>Instances</th><th>Solution</th></tr>
                {zap_rows()}
            </table>
        </div>
    </div>

    <!-- IAC DETAILS -->
    <div class="sec anim d8">
        <div class="sec-title"><span class="icon">🏗️</span> Misconfigurations Infrastructure (IaC)</div>
        <div class="tbl-wrap">
            <table>
                <tr><th>ID</th><th>Titre</th><th>Fichier</th><th>Sévérité</th><th>Résolution</th></tr>
                {iac_rows()}
            </table>
        </div>
    </div>

    <!-- FOOTER -->
    <div class="ftr">
        <p><strong>🛡️ ERP SecurePipeline</strong> — Security Dashboard</p>
        <div class="ftr-tools">
            <span class="ftr-tool">🔍 SonarQube (SAST)</span>
            <span class="ftr-tool">📦 Trivy (SCA + Container + IaC)</span>
            <span class="ftr-tool">🔑 GitLeaks (Secrets)</span>
            <span class="ftr-tool">🌐 OWASP ZAP (DAST)</span>
            <span class="ftr-tool">📋 CycloneDX (SBOM)</span>
        </div>
        <p style="margin-top:0.75rem;font-size:0.72rem">Rapport généré automatiquement par le pipeline DevSecOps • Projet PFE — Farouk & Maha • {datetime.now().year}</p>
    </div>

</div>
</body>
</html>'''

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Security Dashboard généré : {output_file}")
    print(f"   Score: {score}/100 ({sl})")
    print(f"   Vulnérabilités: {tc}C / {th}H / {tm}M / {tl}L")
    print(f"   Secrets: {gitleaks_count} | SBOM: {sbom['total']} composants | IaC: {iac_total} misconfigs")
    return 0


if __name__ == '__main__':
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else 'reports'
    build_number = sys.argv[2] if len(sys.argv) > 2 else '0'
    output_file = f'{reports_dir}/security-dashboard.html'
    sys.exit(generate_html(reports_dir, build_number, output_file))