#!/usr/bin/env python3
"""
Générateur de rapport HTML de sécurité DevSecOps.
Lit les rapports JSON des scanners et génère un dashboard HTML interactif.
"""

import json
import os
import sys
from datetime import datetime

def load_json(filepath):
    """Charge un fichier JSON en tolérant les erreurs."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def parse_trivy(report):
    """Parse un rapport Trivy JSON."""
    stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulns': []}
    for result in report.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            sev = vuln.get('Severity', 'UNKNOWN').lower()
            if sev in stats:
                stats[sev] += 1
            stats['vulns'].append({
                'id': vuln.get('VulnerabilityID', 'N/A'),
                'pkg': vuln.get('PkgName', 'N/A'),
                'severity': vuln.get('Severity', 'N/A'),
                'title': vuln.get('Title', vuln.get('Description', 'N/A'))[:100]
            })
    return stats

def parse_gitleaks(report):
    """Parse un rapport GitLeaks JSON."""
    if isinstance(report, list):
        return len(report)
    return 0

def parse_zap(report):
    """Parse un rapport ZAP JSON."""
    alerts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for site in report.get('site', []):
        for alert in site.get('alerts', []):
            risk = alert.get('riskdesc', '').split(' ')[0].lower()
            if risk in alerts:
                alerts[risk] += 1
    return alerts

def generate_html(reports_dir, build_number, output_file):
    """Génère le rapport HTML."""
    
    # Charger les rapports
    trivy_sca = parse_trivy(load_json(f'{reports_dir}/trivy-sca.json'))
    trivy_image = parse_trivy(load_json(f'{reports_dir}/trivy-image.json'))
    gitleaks_count = parse_gitleaks(load_json(f'{reports_dir}/gitleaks.json'))
    zap_alerts = parse_zap(load_json(f'{reports_dir}/zap-report.json'))
    
    # Charger le résultat de la Security Gate
    gate1 = load_json(f'{reports_dir}/security-gate-1.json')
    gate1_passed = gate1.get('passed', 'N/A')
    
    # Score global
    total_critical = trivy_sca['critical'] + trivy_image['critical']
    total_high = trivy_sca['high'] + trivy_image['high']
    total_medium = trivy_sca['medium'] + trivy_image['medium']
    
    if total_critical > 0:
        score = 30
        score_color = '#ef4444'
        score_label = 'CRITIQUE'
    elif total_high > 5:
        score = 50
        score_color = '#f97316'
        score_label = 'FAIBLE'
    elif total_high > 0:
        score = 75
        score_color = '#eab308'
        score_label = 'ACCEPTABLE'
    else:
        score = 95
        score_color = '#22c55e'
        score_label = 'EXCELLENT'
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERP SecurePipeline — Rapport Sécurité Build #{build_number}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --green: #22c55e;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --purple: #a855f7;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 2rem;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .header h1 {{
            font-size: 1.8rem;
            background: linear-gradient(135deg, var(--blue), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header .meta {{
            color: var(--muted);
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            transition: transform 0.2s;
        }}
        .card:hover {{ transform: translateY(-2px); }}
        .card h3 {{
            color: var(--muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.8rem;
        }}
        .card .value {{
            font-size: 2.5rem;
            font-weight: 700;
        }}
        .card .label {{
            color: var(--muted);
            font-size: 0.85rem;
            margin-top: 0.3rem;
        }}
        .score-card {{
            grid-column: span 2;
            display: flex;
            align-items: center;
            gap: 2rem;
        }}
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 6px solid {score_color};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .score-circle .num {{ font-size: 2.5rem; font-weight: 700; color: {score_color}; }}
        .score-circle .lbl {{ font-size: 0.7rem; color: var(--muted); }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-pass {{ background: #166534; color: #86efac; }}
        .badge-fail {{ background: #991b1b; color: #fca5a5; }}
        .badge-critical {{ background: #991b1b; color: #fca5a5; }}
        .badge-high {{ background: #9a3412; color: #fed7aa; }}
        .badge-medium {{ background: #854d0e; color: #fef08a; }}
        .badge-low {{ background: #1e3a5f; color: #93c5fd; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section-title {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .scanner-row {{
            display: grid;
            grid-template-columns: 200px repeat(4, 1fr) 100px;
            gap: 0.5rem;
            padding: 1rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 0.5rem;
            align-items: center;
        }}
        .scanner-name {{ font-weight: 600; }}
        .footer {{
            text-align: center;
            color: var(--muted);
            font-size: 0.8rem;
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ERP SecurePipeline — Rapport de Sécurité</h1>
        <div class="meta">Build #{build_number} • {timestamp} • Pipeline DevSecOps</div>
    </div>

    <div class="grid">
        <div class="card score-card">
            <div class="score-circle">
                <div class="num">{score}</div>
                <div class="lbl">/100</div>
            </div>
            <div>
                <h3>Score Sécurité Global</h3>
                <div class="value" style="color: {score_color}; font-size: 1.5rem;">{score_label}</div>
                <div class="label">Basé sur l'analyse SAST + SCA + Container Scan + Secrets</div>
            </div>
        </div>

        <div class="card">
            <h3>🔴 Critiques</h3>
            <div class="value" style="color: var(--red);">{total_critical}</div>
            <div class="label">Vulnérabilités critiques</div>
        </div>

        <div class="card">
            <h3>🟠 Élevées</h3>
            <div class="value" style="color: var(--orange);">{total_high}</div>
            <div class="label">Vulnérabilités high</div>
        </div>

        <div class="card">
            <h3>🟡 Moyennes</h3>
            <div class="value" style="color: var(--yellow);">{total_medium}</div>
            <div class="label">Vulnérabilités medium</div>
        </div>

        <div class="card">
            <h3>🔑 Secrets</h3>
            <div class="value" style="color: {'var(--red)' if gitleaks_count > 0 else 'var(--green)'};">{gitleaks_count}</div>
            <div class="label">Secrets détectés dans le code</div>
        </div>

        <div class="card">
            <h3>🚪 Security Gate #1</h3>
            <div class="value">
                <span class="badge {'badge-pass' if gate1_passed else 'badge-fail'}">
                    {'✅ PASSED' if gate1_passed else '❌ FAILED'}
                </span>
            </div>
            <div class="label">Scans statiques (SAST/SCA/Secrets)</div>
        </div>
    </div>

    <h2 class="section-title">📊 Détails par Scanner</h2>

    <div class="scanner-row" style="font-weight: 600; color: var(--muted);">
        <div>Scanner</div>
        <div>🔴 Critical</div>
        <div>🟠 High</div>
        <div>🟡 Medium</div>
        <div>🔵 Low</div>
        <div>Status</div>
    </div>
    <div class="scanner-row">
        <div class="scanner-name">📦 Trivy SCA</div>
        <div>{trivy_sca['critical']}</div>
        <div>{trivy_sca['high']}</div>
        <div>{trivy_sca['medium']}</div>
        <div>{trivy_sca['low']}</div>
        <div><span class="badge {'badge-pass' if trivy_sca['critical'] == 0 else 'badge-fail'}">{'✅' if trivy_sca['critical'] == 0 else '❌'}</span></div>
    </div>
    <div class="scanner-row">
        <div class="scanner-name">🐳 Trivy Image</div>
        <div>{trivy_image['critical']}</div>
        <div>{trivy_image['high']}</div>
        <div>{trivy_image['medium']}</div>
        <div>{trivy_image['low']}</div>
        <div><span class="badge {'badge-pass' if trivy_image['critical'] == 0 else 'badge-fail'}">{'✅' if trivy_image['critical'] == 0 else '❌'}</span></div>
    </div>
    <div class="scanner-row">
        <div class="scanner-name">🔑 GitLeaks</div>
        <div>—</div>
        <div>—</div>
        <div>—</div>
        <div>—</div>
        <div><span class="badge {'badge-pass' if gitleaks_count == 0 else 'badge-fail'}">{gitleaks_count} secret(s)</span></div>
    </div>
    <div class="scanner-row">
        <div class="scanner-name">🌐 OWASP ZAP</div>
        <div>—</div>
        <div>{zap_alerts['high']}</div>
        <div>{zap_alerts['medium']}</div>
        <div>{zap_alerts['low']}</div>
        <div><span class="badge {'badge-pass' if zap_alerts['high'] == 0 else 'badge-fail'}">{'✅' if zap_alerts['high'] == 0 else '❌'}</span></div>
    </div>

    {"<h2 class='section-title' style='margin-top: 2rem;'>🔍 Vulnérabilités Image Docker (Top 10)</h2><table><tr><th>CVE</th><th>Package</th><th>Sévérité</th><th>Description</th></tr>" + ''.join(f"<tr><td>{v['id']}</td><td>{v['pkg']}</td><td><span class='badge badge-{v['severity'].lower()}'>{v['severity']}</span></td><td>{v['title']}</td></tr>" for v in trivy_image['vulns'][:10]) + "</table>" if trivy_image['vulns'] else ""}

    <div class="footer">
        <p>🛡️ ERP SecurePipeline — Rapport généré automatiquement par le pipeline DevSecOps</p>
        <p>Outils : SonarQube (SAST) • Trivy (SCA + Container) • GitLeaks (Secrets) • OWASP ZAP (DAST)</p>
    </div>
</body>
</html>"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Rapport HTML généré : {output_file}")
    return 0

if __name__ == '__main__':
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else 'reports'
    build_number = sys.argv[2] if len(sys.argv) > 2 else '0'
    output_file = f'{reports_dir}/security-dashboard.html'
    
    sys.exit(generate_html(reports_dir, build_number, output_file))