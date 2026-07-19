#!/usr/bin/env python3
"""
ERP SecurePipeline — Générateur de Dashboard Sécurité v2
Lit les rapports JSON des scanners et génère un dashboard HTML premium.
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
                'installed': vuln.get('InstalledVersion', 'N/A'),
                'fixed': vuln.get('FixedVersion', 'N/A'),
                'severity': vuln.get('Severity', 'N/A'),
                'title': (vuln.get('Title', '') or vuln.get('Description', 'N/A'))[:120]
            })
    return stats


def parse_gitleaks(report):
    """Parse un rapport GitLeaks JSON."""
    if isinstance(report, list):
        return len(report)
    return 0


def parse_zap(report):
    """Parse un rapport ZAP JSON."""
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
                'desc': (alert.get('desc', '') or '')[:150],
                'solution': (alert.get('solution', '') or '')[:150]
            })
    return alerts


def parse_sbom(report):
    """Parse un rapport SBOM CycloneDX."""
    components = report.get('components', [])
    return {
        'total': len(components),
        'libraries': len([c for c in components if c.get('type') == 'library']),
        'frameworks': len([c for c in components if c.get('type') == 'framework']),
    }


def parse_iac(report):
    """Parse un rapport Trivy IaC JSON."""
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


def calculate_score(total_critical, total_high, total_medium, secrets, zap_high):
    """Calcul de score granulaire 0-100."""
    score = 100
    score -= total_critical * 25
    score -= total_high * 10
    score -= total_medium * 3
    score -= secrets * 30
    score -= zap_high * 15
    return max(0, min(100, score))


def generate_html(reports_dir, build_number, output_file):
    """Génère le dashboard HTML premium."""

    # Charger tous les rapports
    trivy_sca = parse_trivy(load_json(f'{reports_dir}/trivy-sca.json'))
    trivy_image = parse_trivy(load_json(f'{reports_dir}/trivy-image.json'))
    gitleaks_count = parse_gitleaks(load_json(f'{reports_dir}/gitleaks.json'))
    zap_alerts = parse_zap(load_json(f'{reports_dir}/zap-report.json'))
    sbom = parse_sbom(load_json(f'{reports_dir}/sbom.json'))
    iac = parse_iac(load_json(f'{reports_dir}/trivy-iac.json'))
    gate1 = load_json(f'{reports_dir}/security-gate-1.json')
    gate2 = load_json(f'{reports_dir}/security-gate-2.json')

    gate1_passed = gate1.get('gate_passed', gate1.get('passed', False))
    gate2_passed = gate2.get('gate_passed', gate2.get('passed', False))

    # Totaux
    total_critical = trivy_sca['critical'] + trivy_image['critical']
    total_high = trivy_sca['high'] + trivy_image['high'] + zap_alerts['high']
    total_medium = trivy_sca['medium'] + trivy_image['medium'] + zap_alerts['medium']
    total_low = trivy_sca['low'] + trivy_image['low'] + zap_alerts['low']
    total_all = total_critical + total_high + total_medium + total_low

    score = calculate_score(total_critical, total_high, total_medium, gitleaks_count, zap_alerts['high'])

    if score >= 90:
        score_color = '#22c55e'
        score_label = 'EXCELLENT'
        score_glow = '0 0 30px rgba(34,197,94,0.3)'
    elif score >= 70:
        score_color = '#eab308'
        score_label = 'ACCEPTABLE'
        score_glow = '0 0 30px rgba(234,179,8,0.3)'
    elif score >= 40:
        score_color = '#f97316'
        score_label = 'FAIBLE'
        score_glow = '0 0 30px rgba(249,115,22,0.3)'
    else:
        score_color = '#ef4444'
        score_label = 'CRITIQUE'
        score_glow = '0 0 30px rgba(239,68,68,0.3)'

    # SVG arc pour le score (cercle animé)
    circumference = 2 * 3.14159 * 54
    dash_offset = circumference * (1 - score / 100)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Barres de répartition
    bar_total = max(total_all, 1)
    bar_crit = (total_critical / bar_total) * 100
    bar_high = (total_high / bar_total) * 100
    bar_med = (total_medium / bar_total) * 100
    bar_low = (total_low / bar_total) * 100

    # Table vulnérabilités SCA
    sca_vulns_html = ''
    if trivy_sca['vulns']:
        rows = ''.join(f"""<tr>
            <td><code>{v['id']}</code></td>
            <td>{v['pkg']}</td>
            <td>{v['installed']}</td>
            <td>{v['fixed']}</td>
            <td><span class="badge badge-{v['severity'].lower()}">{v['severity']}</span></td>
            <td class="desc-cell">{v['title']}</td>
        </tr>""" for v in trivy_sca['vulns'][:10])
        sca_vulns_html = f"""
        <div class="section" id="sca-details">
            <h2 class="section-title">📦 Vulnérabilités Dépendances (Top 10)</h2>
            <div class="table-wrap">
            <table>
                <tr><th>CVE</th><th>Package</th><th>Installée</th><th>Corrigée</th><th>Sévérité</th><th>Description</th></tr>
                {rows}
            </table>
            </div>
        </div>"""

    # Table vulnérabilités Image
    image_vulns_html = ''
    if trivy_image['vulns']:
        rows = ''.join(f"""<tr>
            <td><code>{v['id']}</code></td>
            <td>{v['pkg']}</td>
            <td>{v['installed']}</td>
            <td>{v['fixed']}</td>
            <td><span class="badge badge-{v['severity'].lower()}">{v['severity']}</span></td>
            <td class="desc-cell">{v['title']}</td>
        </tr>""" for v in trivy_image['vulns'][:10])
        image_vulns_html = f"""
        <div class="section" id="image-details">
            <h2 class="section-title">🐳 Vulnérabilités Image Docker (Top 10)</h2>
            <div class="table-wrap">
            <table>
                <tr><th>CVE</th><th>Package</th><th>Installée</th><th>Corrigée</th><th>Sévérité</th><th>Description</th></tr>
                {rows}
            </table>
            </div>
        </div>"""

    # Alertes ZAP détaillées
    zap_details_html = ''
    if zap_alerts['details']:
        rows = ''.join(f"""<tr>
            <td>{a['name']}</td>
            <td><span class="badge badge-{a['risk'].split(' ')[0].lower() if a['risk'] != 'N/A' else 'low'}">{a['risk']}</span></td>
            <td>{a['count']}</td>
            <td class="desc-cell">{a['solution']}</td>
        </tr>""" for a in zap_alerts['details'][:10])
        zap_details_html = f"""
        <div class="section" id="zap-details">
            <h2 class="section-title">🌐 Alertes OWASP ZAP (DAST)</h2>
            <div class="table-wrap">
            <table>
                <tr><th>Alerte</th><th>Risque</th><th>Instances</th><th>Solution</th></tr>
                {rows}
            </table>
            </div>
        </div>"""

    # IaC misconfigurations
    iac_html = ''
    if iac['misconfigs']:
        rows = ''.join(f"""<tr>
            <td><code>{m['id']}</code></td>
            <td>{m['title']}</td>
            <td>{m['file']}</td>
            <td><span class="badge badge-{m['severity'].lower()}">{m['severity']}</span></td>
            <td class="desc-cell">{m['resolution']}</td>
        </tr>""" for m in iac['misconfigs'][:10])
        iac_html = f"""
        <div class="section" id="iac-details">
            <h2 class="section-title">🏗️ Misconfigurations Infrastructure (IaC)</h2>
            <div class="table-wrap">
            <table>
                <tr><th>ID</th><th>Titre</th><th>Fichier</th><th>Sévérité</th><th>Résolution</th></tr>
                {rows}
            </table>
            </div>
        </div>"""

    # Pipeline stages
    stages = [
        ('Checkout', True), ('Install & Build', True), ('Unit Tests', True),
        ('Docker Build', True), ('SAST', True), ('SCA', True),
        ('GitLeaks', True), ('Container Scan', True),
        ('Security Gate #1', gate1_passed),
        ('Deploy Staging', True), ('DAST — ZAP', True),
        ('Security Gate #2', gate2_passed if gate2 else True),
    ]

    stages_html = ''.join(f"""
        <div class="stage {'stage-pass' if passed else 'stage-fail'}">
            <div class="stage-icon">{'✅' if passed else '❌'}</div>
            <div class="stage-name">{name}</div>
        </div>
        {'<div class="stage-arrow">→</div>' if i < len(stages) - 1 else ''}
    """ for i, (name, passed) in enumerate(stages))

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERP SecurePipeline — Dashboard Sécurité Build #{build_number}</title>
    <style>
        :root {{
            --bg: #0a0e1a;
            --bg2: #111827;
            --card: rgba(30, 41, 59, 0.7);
            --card-solid: #1e293b;
            --border: rgba(51, 65, 85, 0.5);
            --text: #e2e8f0;
            --muted: #94a3b8;
            --green: #22c55e;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --purple: #a855f7;
            --cyan: #06b6d4;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes scoreAnim {{
            from {{ stroke-dashoffset: {circumference}; }}
            to {{ stroke-dashoffset: {dash_offset}; }}
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        @keyframes glow {{
            0%, 100% {{ box-shadow: 0 0 5px rgba(59,130,246,0.1); }}
            50% {{ box-shadow: 0 0 20px rgba(59,130,246,0.2); }}
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        /* Header */
        .header {{
            text-align: center;
            margin-bottom: 2.5rem;
            padding: 2rem;
            background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(168,85,247,0.1));
            border: 1px solid var(--border);
            border-radius: 16px;
            animation: fadeIn 0.6s ease-out;
        }}
        .header h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, var(--blue), var(--purple), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}
        .header .meta {{
            color: var(--muted);
            font-size: 0.9rem;
        }}
        .header .meta span {{
            display: inline-block;
            margin: 0 0.5rem;
            padding: 0.2rem 0.8rem;
            background: var(--card);
            border-radius: 20px;
            font-size: 0.8rem;
        }}

        /* Navigation */
        .nav {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            animation: fadeIn 0.6s ease-out 0.1s both;
        }}
        .nav a {{
            padding: 0.5rem 1rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--muted);
            text-decoration: none;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        .nav a:hover {{
            background: rgba(59,130,246,0.15);
            color: var(--blue);
            border-color: var(--blue);
        }}

        /* Grid */
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        /* Cards */
        .card {{
            background: var(--card);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            animation: fadeIn 0.6s ease-out both;
        }}
        .card:hover {{
            transform: translateY(-4px);
            border-color: rgba(59,130,246,0.3);
            animation: glow 2s ease-in-out infinite;
        }}
        .card h3 {{
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 1rem;
        }}
        .card .value {{
            font-size: 2.8rem;
            font-weight: 800;
            line-height: 1;
        }}
        .card .label {{
            color: var(--muted);
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }}

        /* Score Card */
        .score-card {{
            grid-column: span 2;
            display: flex;
            align-items: center;
            gap: 2.5rem;
            padding: 2rem;
        }}
        .score-svg {{
            flex-shrink: 0;
            filter: drop-shadow({score_glow});
        }}
        .score-svg circle.bg {{
            fill: none;
            stroke: rgba(51,65,85,0.5);
            stroke-width: 8;
        }}
        .score-svg circle.progress {{
            fill: none;
            stroke: {score_color};
            stroke-width: 8;
            stroke-linecap: round;
            stroke-dasharray: {circumference};
            stroke-dashoffset: {dash_offset};
            transform: rotate(-90deg);
            transform-origin: center;
            animation: scoreAnim 1.5s ease-out;
        }}
        .score-text {{
            font-size: 2.5rem;
            font-weight: 800;
            fill: {score_color};
        }}
        .score-label-svg {{
            font-size: 0.7rem;
            fill: var(--muted);
        }}
        .score-info h3 {{ margin-bottom: 0.3rem; }}
        .score-info .grade {{
            font-size: 1.6rem;
            font-weight: 700;
            color: {score_color};
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.7rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .badge-pass {{ background: rgba(22,163,74,0.2); color: #86efac; border: 1px solid rgba(22,163,74,0.3); }}
        .badge-fail {{ background: rgba(220,38,38,0.2); color: #fca5a5; border: 1px solid rgba(220,38,38,0.3); }}
        .badge-critical {{ background: rgba(220,38,38,0.2); color: #fca5a5; }}
        .badge-high {{ background: rgba(234,88,12,0.2); color: #fed7aa; }}
        .badge-medium {{ background: rgba(161,98,7,0.2); color: #fef08a; }}
        .badge-low {{ background: rgba(30,58,95,0.3); color: #93c5fd; }}
        .badge-info {{ background: rgba(6,182,212,0.2); color: #67e8f9; }}

        /* Distribution bar */
        .dist-bar {{
            display: flex;
            height: 12px;
            border-radius: 6px;
            overflow: hidden;
            margin: 1rem 0;
            background: rgba(51,65,85,0.3);
        }}
        .dist-bar div {{ transition: width 1s ease; }}
        .dist-legend {{
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }}
        .dist-legend span {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.8rem;
            color: var(--muted);
        }}
        .dist-legend .dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }}

        /* Scanner rows */
        .scanner-grid {{
            display: grid;
            gap: 0.5rem;
        }}
        .scanner-row {{
            display: grid;
            grid-template-columns: 200px repeat(4, 1fr) 120px;
            gap: 0.5rem;
            padding: 1rem 1.2rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            align-items: center;
            transition: all 0.2s;
        }}
        .scanner-row:hover {{
            background: rgba(30,41,59,0.9);
            border-color: rgba(59,130,246,0.3);
        }}
        .scanner-row.header-row {{
            background: transparent;
            border: none;
            font-weight: 600;
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .scanner-name {{ font-weight: 600; }}

        /* Pipeline stages */
        .pipeline {{
            display: flex;
            align-items: center;
            gap: 0.3rem;
            overflow-x: auto;
            padding: 1rem 0;
            flex-wrap: wrap;
        }}
        .stage {{
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.3rem;
            padding: 0.6rem 0.8rem;
            border-radius: 10px;
            font-size: 0.7rem;
            min-width: 85px;
            text-align: center;
            transition: all 0.2s;
        }}
        .stage-pass {{
            background: rgba(22,163,74,0.15);
            border: 1px solid rgba(22,163,74,0.3);
            color: #86efac;
        }}
        .stage-fail {{
            background: rgba(220,38,38,0.15);
            border: 1px solid rgba(220,38,38,0.3);
            color: #fca5a5;
        }}
        .stage-icon {{ font-size: 1.2rem; }}
        .stage-name {{ font-weight: 500; line-height: 1.2; }}
        .stage-arrow {{ color: var(--muted); font-size: 1.2rem; flex-shrink: 0; }}

        /* Sections */
        .section {{
            margin-bottom: 2.5rem;
            animation: fadeIn 0.6s ease-out both;
        }}
        .section-title {{
            font-size: 1.4rem;
            margin-bottom: 1.2rem;
            padding-bottom: 0.8rem;
            border-bottom: 2px solid var(--border);
            background: linear-gradient(135deg, var(--text), var(--muted));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        /* Tables */
        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 0.9rem 1rem;
            color: var(--muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            background: rgba(15,23,42,0.5);
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(51,65,85,0.3);
            font-size: 0.85rem;
        }}
        tr:hover td {{
            background: rgba(59,130,246,0.05);
        }}
        code {{
            background: rgba(59,130,246,0.1);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: var(--cyan);
        }}
        .desc-cell {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: var(--muted);
        }}

        /* Footer */
        .footer {{
            text-align: center;
            color: var(--muted);
            font-size: 0.8rem;
            margin-top: 3rem;
            padding: 2rem;
            border-top: 1px solid var(--border);
            background: linear-gradient(0deg, rgba(59,130,246,0.03), transparent);
            border-radius: 16px 16px 0 0;
        }}
        .footer .tools {{
            display: flex;
            justify-content: center;
            gap: 1.5rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}
        .footer .tool {{
            padding: 0.3rem 0.8rem;
            background: var(--card);
            border-radius: 20px;
            font-size: 0.75rem;
            border: 1px solid var(--border);
        }}

        @media (max-width: 768px) {{
            .score-card {{ grid-column: span 1; flex-direction: column; text-align: center; }}
            .scanner-row {{ grid-template-columns: 1fr; gap: 0.3rem; }}
            .scanner-row.header-row {{ display: none; }}
            .grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>🛡️ ERP SecurePipeline — Dashboard Sécurité</h1>
        <div class="meta">
            <span>🔨 Build #{build_number}</span>
            <span>🕐 {timestamp}</span>
            <span>📦 {sbom['total']} composants</span>
            <span>{'🟢 Pipeline OK' if gate1_passed else '🔴 Pipeline FAILED'}</span>
        </div>
    </div>

    <nav class="nav">
        <a href="#overview">📊 Vue d'ensemble</a>
        <a href="#scanners">🔍 Scanners</a>
        <a href="#pipeline">🔄 Pipeline</a>
        <a href="#sca-details">📦 SCA</a>
        <a href="#image-details">🐳 Image</a>
        <a href="#zap-details">🌐 DAST</a>
        <a href="#iac-details">🏗️ IaC</a>
    </nav>

    <!-- VUE D'ENSEMBLE -->
    <div class="grid" id="overview">
        <div class="card score-card" style="animation-delay: 0.1s">
            <svg class="score-svg" width="140" height="140" viewBox="0 0 120 120">
                <circle class="bg" cx="60" cy="60" r="54"/>
                <circle class="progress" cx="60" cy="60" r="54"/>
                <text class="score-text" x="60" y="55" text-anchor="middle">{score}</text>
                <text class="score-label-svg" x="60" y="72" text-anchor="middle">/100</text>
            </svg>
            <div class="score-info">
                <h3>Score Sécurité Global</h3>
                <div class="grade">{score_label}</div>
                <div class="label">Basé sur SAST + SCA + Container + Secrets + DAST</div>
                <div style="margin-top: 1rem;">
                    <span class="badge {'badge-pass' if gate1_passed else 'badge-fail'}">Gate #1: {'PASSED' if gate1_passed else 'FAILED'}</span>
                    <span class="badge {'badge-pass' if gate2_passed else 'badge-fail'}" style="margin-left: 0.5rem;">Gate #2: {'PASSED' if gate2_passed else 'FAILED'}</span>
                </div>
            </div>
        </div>

        <div class="card" style="animation-delay: 0.2s">
            <h3>🔴 Critiques</h3>
            <div class="value" style="color: var(--red);">{total_critical}</div>
            <div class="label">Vulnérabilités critiques</div>
        </div>

        <div class="card" style="animation-delay: 0.25s">
            <h3>🟠 Élevées</h3>
            <div class="value" style="color: var(--orange);">{total_high}</div>
            <div class="label">Vulnérabilités high</div>
        </div>

        <div class="card" style="animation-delay: 0.3s">
            <h3>🟡 Moyennes</h3>
            <div class="value" style="color: var(--yellow);">{total_medium}</div>
            <div class="label">Vulnérabilités medium</div>
        </div>

        <div class="card" style="animation-delay: 0.35s">
            <h3>🔵 Faibles</h3>
            <div class="value" style="color: var(--blue);">{total_low}</div>
            <div class="label">Vulnérabilités low</div>
        </div>

        <div class="card" style="animation-delay: 0.4s">
            <h3>🔑 Secrets</h3>
            <div class="value" style="color: {'var(--red)' if gitleaks_count > 0 else 'var(--green)'};">{gitleaks_count}</div>
            <div class="label">Secrets détectés (GitLeaks)</div>
        </div>

        <div class="card" style="animation-delay: 0.45s">
            <h3>📦 SBOM</h3>
            <div class="value" style="color: var(--cyan);">{sbom['total']}</div>
            <div class="label">{sbom['libraries']} libs • {sbom['frameworks']} frameworks</div>
        </div>

        <div class="card" style="animation-delay: 0.5s">
            <h3>🏗️ IaC</h3>
            <div class="value" style="color: {'var(--red)' if iac['critical'] > 0 else 'var(--orange)' if iac['high'] > 0 else 'var(--green)'};">{iac['critical'] + iac['high'] + iac['medium'] + iac['low']}</div>
            <div class="label">Misconfigurations K8s</div>
        </div>
    </div>

    <!-- DISTRIBUTION -->
    <div class="section">
        <h2 class="section-title">📈 Répartition des Vulnérabilités</h2>
        <div class="card">
            <div class="dist-bar">
                <div style="width: {bar_crit}%; background: var(--red);"></div>
                <div style="width: {bar_high}%; background: var(--orange);"></div>
                <div style="width: {bar_med}%; background: var(--yellow);"></div>
                <div style="width: {bar_low}%; background: var(--blue);"></div>
            </div>
            <div class="dist-legend">
                <span><span class="dot" style="background: var(--red);"></span>Critical ({total_critical})</span>
                <span><span class="dot" style="background: var(--orange);"></span>High ({total_high})</span>
                <span><span class="dot" style="background: var(--yellow);"></span>Medium ({total_medium})</span>
                <span><span class="dot" style="background: var(--blue);"></span>Low ({total_low})</span>
                <span style="margin-left: auto; font-weight: 600; color: var(--text);">Total: {total_all}</span>
            </div>
        </div>
    </div>

    <!-- SCANNERS -->
    <div class="section" id="scanners">
        <h2 class="section-title">🔍 Résultats par Scanner</h2>
        <div class="scanner-grid">
            <div class="scanner-row header-row">
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
                <div><span class="badge {'badge-pass' if trivy_sca['critical'] == 0 and trivy_sca['high'] == 0 else 'badge-fail'}">{'✅ Clean' if trivy_sca['critical'] == 0 and trivy_sca['high'] == 0 else '❌ Issues'}</span></div>
            </div>
            <div class="scanner-row">
                <div class="scanner-name">🐳 Trivy Image</div>
                <div>{trivy_image['critical']}</div>
                <div>{trivy_image['high']}</div>
                <div>{trivy_image['medium']}</div>
                <div>{trivy_image['low']}</div>
                <div><span class="badge {'badge-pass' if trivy_image['critical'] == 0 and trivy_image['high'] == 0 else 'badge-fail'}">{'✅ Clean' if trivy_image['critical'] == 0 and trivy_image['high'] == 0 else '❌ Issues'}</span></div>
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
                <div><span class="badge {'badge-pass' if zap_alerts['high'] == 0 else 'badge-fail'}">{'✅ Clean' if zap_alerts['high'] == 0 else '❌ Issues'}</span></div>
            </div>
            <div class="scanner-row">
                <div class="scanner-name">🏗️ Trivy IaC</div>
                <div>{iac['critical']}</div>
                <div>{iac['high']}</div>
                <div>{iac['medium']}</div>
                <div>{iac['low']}</div>
                <div><span class="badge {'badge-pass' if iac['critical'] == 0 and iac['high'] == 0 else 'badge-fail'}">{'✅ Clean' if iac['critical'] == 0 and iac['high'] == 0 else '❌ Issues'}</span></div>
            </div>
        </div>
    </div>

    <!-- PIPELINE -->
    <div class="section" id="pipeline">
        <h2 class="section-title">🔄 Pipeline CI/CD — Stages</h2>
        <div class="card">
            <div class="pipeline">
                {stages_html}
            </div>
        </div>
    </div>

    <!-- TABLES DÉTAILLÉES -->
    {sca_vulns_html}
    {image_vulns_html}
    {zap_details_html}
    {iac_html}

    <div class="footer">
        <p>🛡️ ERP SecurePipeline — Dashboard généré automatiquement par le pipeline DevSecOps</p>
        <div class="tools">
            <span class="tool">🔍 SonarQube (SAST)</span>
            <span class="tool">📦 Trivy (SCA + Container + IaC)</span>
            <span class="tool">🔑 GitLeaks (Secrets)</span>
            <span class="tool">🌐 OWASP ZAP (DAST)</span>
            <span class="tool">📋 CycloneDX (SBOM)</span>
        </div>
        <p style="margin-top: 1rem; font-size: 0.7rem;">Projet PFE — Farouk & Maha — {datetime.now().year}</p>
    </div>

</div>
</body>
</html>"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Dashboard sécurité généré : {output_file}")
    print(f"   Score: {score}/100 ({score_label})")
    print(f"   Vulnérabilités: {total_critical} Critical, {total_high} High, {total_medium} Medium, {total_low} Low")
    print(f"   Secrets: {gitleaks_count} | SBOM: {sbom['total']} composants | IaC: {iac['critical']+iac['high']+iac['medium']+iac['low']} misconfigs")
    return 0


if __name__ == '__main__':
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else 'reports'
    build_number = sys.argv[2] if len(sys.argv) > 2 else '0'
    output_file = f'{reports_dir}/security-dashboard.html'

    sys.exit(generate_html(reports_dir, build_number, output_file))