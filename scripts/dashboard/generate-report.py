#!/usr/bin/env python3
"""
ERP SecurePipeline — Dashboard Sécurité v4 (Enterprise Edition)
Génère un dashboard HTML professionnel et épuré à partir des rapports de scan.
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

    tc = trivy_sca['critical'] + trivy_image['critical'] + iac['critical']
    th = trivy_sca['high'] + trivy_image['high'] + zap['high'] + iac['high']
    tm = trivy_sca['medium'] + trivy_image['medium'] + zap['medium'] + iac['medium']
    tl = trivy_sca['low'] + trivy_image['low'] + zap['low'] + iac['low']
    ta = tc + th + tm + tl
    iac_total = iac['critical'] + iac['high'] + iac['medium'] + iac['low']

    score = calc_score(tc, th, tm, gitleaks_count, zap['high'])

    if score >= 90:
        sc, sl = '#2ea043', 'A'
    elif score >= 70:
        sc, sl = '#d29922', 'B'
    elif score >= 40:
        sc, sl = '#f0883e', 'C'
    else:
        sc, sl = '#f85149', 'D'

    circ = 2 * 3.14159 * 58
    offset = circ * (1 - score / 100)
    ts = datetime.now().strftime('%d %B %Y - %H:%M')

    bt = max(ta, 1)

    def vuln_rows(vulns, limit=12):
        if not vulns:
            return '<tr><td colspan="6" class="empty-state">Aucune vulnérabilité détectée.</td></tr>'
        return ''.join(f'''<tr>
            <td class="mono">{v['id']}</td>
            <td><strong>{v['pkg']}</strong></td>
            <td class="mono muted">{v['installed']}</td>
            <td class="mono muted">{v['fixed'] if v['fixed'] != 'N/A' else '—'}</td>
            <td><span class="badge sev-{v['severity'].lower()}">{v['severity']}</span></td>
            <td class="truncate" title="{v['title']}">{v['title']}</td>
        </tr>''' for v in vulns[:limit])

    def iac_rows():
        if not iac['misconfigs']:
            return '<tr><td colspan="5" class="empty-state">Aucune misconfiguration d\'infrastructure détectée.</td></tr>'
        return ''.join(f'''<tr>
            <td class="mono">{m['id']}</td>
            <td>{m['title']}</td>
            <td class="mono muted">{m['file']}</td>
            <td><span class="badge sev-{m['severity'].lower()}">{m['severity']}</span></td>
            <td class="truncate" title="{m['resolution']}">{m['resolution']}</td>
        </tr>''' for m in iac['misconfigs'][:10])

    def zap_rows():
        if not zap['details']:
            return '<tr><td colspan="4" class="empty-state">Aucune alerte dynamique DAST détectée.</td></tr>'
        return ''.join(f'''<tr>
            <td>{a['name']}</td>
            <td><span class="badge sev-{a['risk'].split(' ')[0].lower() if a['risk'] != 'N/A' else 'info'}">{a['risk']}</span></td>
            <td class="text-center">{a['count']}</td>
            <td class="truncate" title="{a['solution']}">{a['solution']}</td>
        </tr>''' for a in zap['details'][:10])

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'Audit DevSecOps - Build #{build_number}</title>
<style>
:root {{
    --bg-color: #0d1117;
    --panel-bg: #161b22;
    --border-color: #30363d;
    --text-main: #c9d1d9;
    --text-muted: #8b949e;
    --color-critical: #ff7b72;
    --color-high: #f0883e;
    --color-medium: #d29922;
    --color-low: #58a6ff;
    --color-success: #2ea043;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
    font-family: var(--font-sans);
    background-color: var(--bg-color);
    color: var(--text-main);
    line-height: 1.5;
    font-size: 14px;
    padding: 2rem;
}}

.container {{
    max-width: 1200px;
    margin: 0 auto;
}}

/* Header */
.header {{
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
}}
.header h1 {{
    font-size: 24px;
    font-weight: 600;
    color: #fff;
    margin-bottom: 0.5rem;
}}
.header-meta {{
    color: var(--text-muted);
    font-size: 13px;
    display: flex;
    gap: 1.5rem;
}}
.header-meta span {{
    display: flex;
    align-items: center;
    gap: 6px;
}}

/* Grid & Cards */
.summary-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
}}
.card {{
    background-color: var(--panel-bg);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1.25rem;
}}
.card-score {{
    grid-column: span 5;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.score-details {{
    display: flex;
    gap: 3rem;
}}
.metric-group h3 {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 4px;
}}
.metric-group .val {{
    font-size: 28px;
    font-weight: 600;
    color: #fff;
}}
.card-title {{
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    font-weight: 600;
    margin-bottom: 8px;
}}
.card-number {{
    font-size: 24px;
    font-weight: 600;
}}

/* Colors */
.text-critical {{ color: var(--color-critical); }}
.text-high {{ color: var(--color-high); }}
.text-medium {{ color: var(--color-medium); }}
.text-low {{ color: var(--color-low); }}
.text-success {{ color: var(--color-success); }}

/* Distribution Bar */
.dist-bar-container {{
    margin-top: 2rem;
    margin-bottom: 2rem;
}}
.dist-bar {{
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    background-color: var(--border-color);
    margin-bottom: 1rem;
}}
.dist-legend {{
    display: flex;
    gap: 1.5rem;
    font-size: 12px;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 6px;
}}
.dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
}}

/* Tables */
.section-title {{
    font-size: 18px;
    font-weight: 600;
    margin-top: 2.5rem;
    margin-bottom: 1rem;
    color: #fff;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.5rem;
}}
.table-wrapper {{
    background-color: var(--panel-bg);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    overflow-x: auto;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
}}
th {{
    background-color: rgba(255,255,255,0.02);
    padding: 10px 16px;
    font-size: 12px;
    color: var(--text-muted);
    font-weight: 600;
    border-bottom: 1px solid var(--border-color);
}}
td {{
    padding: 10px 16px;
    border-bottom: 1px solid var(--border-color);
    font-size: 13px;
}}
tr:last-child td {{ border-bottom: none; }}
.empty-state {{
    text-align: center;
    color: var(--text-muted);
    padding: 2rem !important;
    font-style: italic;
}}

/* Utilities */
.mono {{ font-family: var(--font-mono); font-size: 12px; }}
.muted {{ color: var(--text-muted); }}
.truncate {{ max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.text-center {{ text-align: center; }}

/* Badges */
.badge {{
    padding: 2px 8px;
    border-radius: 2em;
    font-size: 11px;
    font-weight: 500;
    border: 1px solid transparent;
    text-transform: capitalize;
}}
.sev-critical {{ color: var(--color-critical); border-color: rgba(255,123,114,0.3); background: rgba(255,123,114,0.1); }}
.sev-high {{ color: var(--color-high); border-color: rgba(240,136,62,0.3); background: rgba(240,136,62,0.1); }}
.sev-medium {{ color: var(--color-medium); border-color: rgba(210,153,34,0.3); background: rgba(210,153,34,0.1); }}
.sev-low {{ color: var(--color-low); border-color: rgba(88,166,255,0.3); background: rgba(88,166,255,0.1); }}
.sev-info {{ color: var(--text-muted); border-color: var(--border-color); background: transparent; }}

.gate-badge {{
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    background-color: var(--panel-bg);
    border: 1px solid var(--border-color);
}}
.gate-pass {{ border-left: 3px solid var(--color-success); }}
.gate-fail {{ border-left: 3px solid var(--color-critical); }}

/* Footer */
.footer {{
    margin-top: 4rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
}}
.footer p {{ margin-bottom: 4px; }}
.footer-tech {{
    display: flex;
    justify-content: center;
    gap: 1rem;
    margin-top: 1rem;
    opacity: 0.7;
}}
</style>
</head>
<body>

<div class="container">
    <div class="header">
        <div>
            <h1>Rapport d'Audit DevSecOps</h1>
            <div class="header-meta">
                <span><strong>Application:</strong> ERP SecurePipeline</span>
                <span><strong>Build:</strong> #{build_number}</span>
                <span><strong>Date:</strong> {ts}</span>
            </div>
        </div>
        <div>
            <span class="gate-badge {'gate-pass' if g1p else 'gate-fail'}">Gate 1: {'PASSED' if g1p else 'FAILED'}</span>
            <span class="gate-badge {'gate-pass' if g2p else 'gate-fail'}" style="margin-left:8px;">Gate 2: {'PASSED' if g2p else 'FAILED'}</span>
        </div>
    </div>

    <div class="summary-grid">
        <div class="card card-score">
            <div class="metric-group">
                <h3>Note de Sécurité</h3>
                <div class="val" style="color: {sc}; font-size: 36px;">{sl} <span style="font-size: 16px; color: var(--text-muted); font-weight: 400;">({score}/100)</span></div>
            </div>
            <div class="score-details">
                <div class="metric-group">
                    <h3>Total Vulnérabilités</h3>
                    <div class="val">{ta}</div>
                </div>
                <div class="metric-group">
                    <h3>Composants Analysés</h3>
                    <div class="val">{sbom['total']}</div>
                </div>
                <div class="metric-group">
                    <h3>Secrets Fuités</h3>
                    <div class="val {'text-critical' if gitleaks_count > 0 else 'text-success'}">{gitleaks_count}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Critique</div>
            <div class="card-number text-critical">{tc}</div>
        </div>
        <div class="card">
            <div class="card-title">Élevé</div>
            <div class="card-number text-high">{th}</div>
        </div>
        <div class="card">
            <div class="card-title">Moyen</div>
            <div class="card-number text-medium">{tm}</div>
        </div>
        <div class="card">
            <div class="card-title">Faible</div>
            <div class="card-number text-low">{tl}</div>
        </div>
        <div class="card">
            <div class="card-title">Misconfigs IaC</div>
            <div class="card-number {'text-high' if iac_total > 0 else 'text-success'}">{iac_total}</div>
        </div>
    </div>

    <div class="dist-bar-container">
        <div class="dist-bar">
            <div style="width: {(tc/bt)*100:.1f}%; background-color: var(--color-critical);"></div>
            <div style="width: {(th/bt)*100:.1f}%; background-color: var(--color-high);"></div>
            <div style="width: {(tm/bt)*100:.1f}%; background-color: var(--color-medium);"></div>
            <div style="width: {(tl/bt)*100:.1f}%; background-color: var(--color-low);"></div>
        </div>
        <div class="dist-legend">
            <div class="legend-item"><div class="dot" style="background-color: var(--color-critical);"></div> Critique ({tc})</div>
            <div class="legend-item"><div class="dot" style="background-color: var(--color-high);"></div> Élevé ({th})</div>
            <div class="legend-item"><div class="dot" style="background-color: var(--color-medium);"></div> Moyen ({tm})</div>
            <div class="legend-item"><div class="dot" style="background-color: var(--color-low);"></div> Faible ({tl})</div>
        </div>
    </div>

    <h2 class="section-title">Analyse Composition Logicielle (Trivy SCA)</h2>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>CVE</th><th>Composant</th><th>Version Installée</th><th>Version Corrigée</th><th>Sévérité</th><th>Description</th></tr></thead>
            <tbody>{vuln_rows(trivy_sca['vulns'])}</tbody>
        </table>
    </div>

    <h2 class="section-title">Analyse Image Conteneur (Trivy Image)</h2>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>CVE</th><th>Composant</th><th>Version Installée</th><th>Version Corrigée</th><th>Sévérité</th><th>Description</th></tr></thead>
            <tbody>{vuln_rows(trivy_image['vulns'])}</tbody>
        </table>
    </div>

    <h2 class="section-title">Analyse Infrastructure as Code (Trivy IaC)</h2>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>ID</th><th>Règle</th><th>Fichier Cible</th><th>Sévérité</th><th>Résolution Recommandée</th></tr></thead>
            <tbody>{iac_rows()}</tbody>
        </table>
    </div>

    <h2 class="section-title">Analyse Dynamique (OWASP ZAP)</h2>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Type d'Alerte</th><th>Niveau de Risque</th><th>Occurrences</th><th>Solution Recommandée</th></tr></thead>
            <tbody>{zap_rows()}</tbody>
        </table>
    </div>

    <div class="footer">
        <p><strong>Projet de Fin d'Études — EPI Sousse</strong></p>
        <p>Réalisé par Farouk Mestiri & Maha | Supervisé par Dr. Bayrem Triki</p>
        <div class="footer-tech">
            <span>Powered by: Jenkins CI/CD • SonarQube • Trivy • GitLeaks • OWASP ZAP</span>
        </div>
    </div>

</div>

</body>
</html>'''

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Security Dashboard (Enterprise Edition) généré : {output_file}")
    return 0

if __name__ == '__main__':
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else 'reports'
    build_number = sys.argv[2] if len(sys.argv) > 2 else '0'
    output_file = f'{reports_dir}/security-dashboard.html'
    sys.exit(generate_html(reports_dir, build_number, output_file))