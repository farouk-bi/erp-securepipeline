#!/usr/bin/env python3
"""
ERP SecurePipeline — Module Security Gate
Agrège les résultats de tous les scanners et prend une décision Go/No-Go.
"""

import json
import sys
import os
from datetime import datetime


class SecurityGate:
    def __init__(self, reports_dir="reports"):
        self.reports_dir = reports_dir
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "scanners": {},
            "total_critical": 0,
            "total_high": 0,
            "total_medium": 0,
            "total_low": 0,
            "secrets_found": 0,
            "gate_passed": False,
            "failure_reasons": []
        }

    def parse_trivy_sca(self):
        """Parse le rapport Trivy SCA (dépendances)."""
        filepath = os.path.join(self.reports_dir, "trivy-sca.json")
        if not os.path.exists(filepath):
            print(f"------------------------ Trivy SCA report not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            data = json.load(f)

        critical = high = medium = low = 0
        
        results = data.get("Results", [])
        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").upper()
                if severity == "CRITICAL":
                    critical += 1
                elif severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                elif severity == "LOW":
                    low += 1

        self.results["scanners"]["trivy_sca"] = {
            "critical": critical, "high": high,
            "medium": medium, "low": low
        }
        self.results["total_critical"] += critical
        self.results["total_high"] += high
        self.results["total_medium"] += medium
        self.results["total_low"] += low

        print(f"------------ Trivy SCA: {critical} Critical, {high} High, {medium} Medium, {low} Low")

    def parse_trivy_image(self):
        """Parse le rapport Trivy Container Scan."""
        filepath = os.path.join(self.reports_dir, "trivy-image.json")
        if not os.path.exists(filepath):
            print(f"------------ Trivy Image report not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            data = json.load(f)

        critical = high = medium = low = 0

        results = data.get("Results", [])
        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").upper()
                if severity == "CRITICAL":
                    critical += 1
                elif severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                elif severity == "LOW":
                    low += 1

        self.results["scanners"]["trivy_image"] = {
            "critical": critical, "high": high,
            "medium": medium, "low": low
        }
        self.results["total_critical"] += critical
        self.results["total_high"] += high
        self.results["total_medium"] += medium
        self.results["total_low"] += low

        print(f"------------ Trivy Image: {critical} Critical, {high} High, {medium} Medium, {low} Low")

    def parse_gitleaks(self):
        """Parse le rapport GitLeaks."""
        filepath = os.path.join(self.reports_dir, "gitleaks.json")
        if not os.path.exists(filepath):
            print(f"------------ GitLeaks report not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

        secrets_count = len(data) if isinstance(data, list) else 0
        self.results["secrets_found"] = secrets_count
        self.results["scanners"]["gitleaks"] = {"secrets_found": secrets_count}

        print(f"------------ GitLeaks: {secrets_count} secrets found")

    def parse_zap(self):
        """Parse le rapport OWASP ZAP."""
        filepath = os.path.join(self.reports_dir, "zap-report.json")
        if not os.path.exists(filepath):
            print(f"------------ ZAP report not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            data = json.load(f)

        high = medium = low = info = 0

        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskcode", "0")
                instances = len(alert.get("instances", []))
                count = max(instances, 1)
                if risk == "3":
                    high += count
                elif risk == "2":
                    medium += count
                elif risk == "1":
                    low += count
                else:
                    info += count

        self.results["scanners"]["zap"] = {
            "high": high, "medium": medium,
            "low": low, "info": info
        }
        self.results["total_high"] += high
        self.results["total_medium"] += medium
        self.results["total_low"] += low

        print(f"------------ OWASP ZAP: {high} High, {medium} Medium, {low} Low, {info} Info")

    def evaluate_gate(self, gate_number=1):
        """Évaluer la Security Gate."""
        print(f"\n{'='*60}")
        print(f"  SECURITY GATE #{gate_number} — ÉVALUATION")
        print(f"{'='*60}\n")

        passed = True
        reasons = []

        # Critère 1 : 0 vulnérabilité Critical
        if self.results["total_critical"] > 0:
            passed = False
            reasons.append(f"------------  {self.results['total_critical']} vulnérabilités CRITICAL détectées")

        # Critère 2 : 0 vulnérabilité High
        if self.results["total_high"] > 0:
            reasons.append(f"------------   {self.results['total_high']} vulnérabilités HIGH détectées (non bloquantes)")

        # Critère 3 : 0 secret détecté
        if self.results["secrets_found"] > 0:
            passed = False
            reasons.append(f"------------  {self.results['secrets_found']} secrets détectés dans le code")

        # Critère 4 : Alertes Medium (warning, pas bloquant si < 5)
        if self.results["total_medium"] > 5:
            reasons.append(f"------------   {self.results['total_medium']} vulnérabilités MEDIUM (> seuil de 5)")
            

        self.results["gate_passed"] = passed
        self.results["failure_reasons"] = reasons

        # Afficher le résultat
        for reason in reasons:
            print(f"  {reason}")

        if not reasons:
            print("   Aucun problème critique détecté")

        print(f"\n{'='*60}")
        if passed:
            print(f"   SECURITY GATE #{gate_number} : PASSED")
        else:
            print(f"   SECURITY GATE #{gate_number} : FAILED")
        print(f"{'='*60}\n")

        # Sauvegarder le rapport de la gate
        report_path = os.path.join(self.reports_dir, f"security-gate-{gate_number}.json")
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f" Rapport sauvegardé : {report_path}")

        return passed


def main():
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    gate_number = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    gate = SecurityGate(reports_dir)

    if gate_number == 1:
        # Gate 1 : après les scans statiques (SAST, SCA, Secrets, Container)
        print(" Security Gate #1 — Scans statiques\n")
        gate.parse_trivy_sca()
        gate.parse_trivy_image()
        gate.parse_gitleaks()
    elif gate_number == 2:
        # Gate 2 : après le scan dynamique (DAST)
        print(" Security Gate #2 — Scan dynamique (DAST)\n")
        gate.parse_zap()

    passed = gate.evaluate_gate(gate_number)

    # Code de sortie : 0 = passed, 1 = failed
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()