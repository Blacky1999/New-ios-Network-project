#!/usr/bin/env python3
"""
Master-Script für Netzwerk-Heuristiken
Führt alle Tools zusammen und bietet eine einheitliche Schnittstelle.
"""

import argparse
import json
import sys
import os
from datetime import datetime
from typing import Dict, List

# Importiere alle Tools
from dns_probing import DNSProbing
from dns_leak_test import DNSLeakTester
from firewall_detector import FirewallDetector
from common_paths_scanner import CommonPathsScanner

class NetworkHeuristicsSuite:
    def __init__(self):
        self.dns_prober = DNSProbing()
        self.dns_leak_tester = DNSLeakTester()
        self.firewall_detector = FirewallDetector()
        self.paths_scanner = CommonPathsScanner()
        self.results = {}
        
    def run_dns_analysis(self, domain: str, full_scan: bool = False) -> Dict:
        """Führt DNS-Analyse durch."""
        print(f"🔍 Führe DNS-Analyse durch für: {domain}")
        
        # Standard-DNS-Probing
        dns_results = self.dns_prober.probe_all_servers(domain)
        
        if full_scan:
            # Erweiterte Tests
            hijack_results = self.dns_prober.detect_dns_hijacking(domain)
            scan_results = self.dns_prober.scan_common_records(domain)
            
            dns_results['hijack_analysis'] = hijack_results
            dns_results['record_scan'] = scan_results
        
        self.results['dns_analysis'] = dns_results
        return dns_results
    
    def run_dns_leak_test(self, test_name: str = None) -> Dict:
        """Führt DNS-Leak-Test durch."""
        print(f"🔍 Führe DNS-Leak-Test durch: {test_name or 'Standard-Test'}")
        
        leak_results = self.dns_leak_tester.test_dns_leak(test_name)
        self.results['dns_leak_test'] = leak_results
        
        return leak_results
    
    def run_firewall_detection(self, target: str, full_scan: bool = False) -> Dict:
        """Führt Firewall-Erkennung durch."""
        print(f"🔥 Führe Firewall-Erkennung durch für: {target}")
        
        # Standard-Firewall-Erkennung
        firewall_results = self.firewall_detector.detect_firewall_by_response(target)
        
        if full_scan:
            # Erweiterte Tests
            port_scan = self.firewall_detector.scan_ports(target)
            system_firewall = self.firewall_detector.detect_system_firewall()
            bypass_test = self.firewall_detector.bypass_firewall_detection(target)
            
            firewall_results['port_scan'] = port_scan
            firewall_results['system_firewall'] = system_firewall
            firewall_results['bypass_analysis'] = bypass_test
        
        self.results['firewall_detection'] = firewall_results
        return firewall_results
    
    def run_paths_scan(self, base_url: str, mode: str = 'intelligent') -> Dict:
        """Führt Common-Paths-Scan durch."""
        print(f"🗂️ Führe Common-Paths-Scan durch für: {base_url}")
        
        if mode == 'intelligent':
            paths_results = self.paths_scanner.intelligent_scan(base_url)
        elif mode == 'common':
            paths_results = self.paths_scanner.scan_common_paths(base_url)
        elif mode == 'extensions':
            paths_results = self.paths_scanner.scan_file_extensions(base_url)
        else:
            paths_results = self.paths_scanner.generate_wordlist_scan(base_url)
        
        self.results['paths_scan'] = paths_results
        return paths_results
    
    def run_comprehensive_analysis(self, target: str, target_type: str = 'auto') -> Dict:
        """Führt eine umfassende Analyse aller Aspekte durch."""
        print(f"🚀 Starte umfassende Analyse für: {target}")
        start_time = datetime.now()
        
        # Bestimme Zieltyp automatisch
        if target_type == 'auto':
            target_type = self._determine_target_type(target)
        
        print(f"Erkannter Zieltyp: {target_type}")
        
        # Führe je nach Zieltyp verschiedene Tests durch
        if target_type == 'domain':
            self._run_domain_analysis(target)
        elif target_type == 'ip':
            self._run_ip_analysis(target)
        elif target_type == 'url':
            self._run_url_analysis(target)
        else:
            print(f"Unbekannter Zieltyp für: {target}")
            return {}
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Erstelle Zusammenfassung
        summary = self._create_analysis_summary(duration)
        self.results['analysis_summary'] = summary
        
        return self.results
    
    def _determine_target_type(self, target: str) -> str:
        """Bestimmt automatisch den Zieltyp."""
        import re
        
        # URL-Muster
        if target.startswith(('http://', 'https://')):
            return 'url'
        
        # IP-Adresse
        ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
        if ip_pattern.match(target):
            return 'ip'
        
        # Domain-Name
        domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if domain_pattern.match(target):
            return 'domain'
        
        # Standard
        return 'domain'
    
    def _run_domain_analysis(self, domain: str):
        """Führt Domain-spezifische Analyse durch."""
        print(f"\n📡 Analysiere Domain: {domain}")
        
        # DNS-Analyse
        dns_results = self.run_dns_analysis(domain, full_scan=True)
        print(f"  - DNS-Server getestet: {dns_results['summary']['total_queries']}")
        print(f"  - Blockierte DNS-Anfragen: {dns_results['summary']['blocked']}")
        
        # DNS-Leak-Test
        leak_results = self.run_dns_leak_test(f"domain_{domain}")
        print(f"  - DNS-Leaks gefunden: {leak_results['summary']['leaks_found']}")
        print(f"  - Risikostufe: {leak_results['summary']['risk_level'].upper()}")
    
    def _run_ip_analysis(self, ip: str):
        """Führt IP-spezifische Analyse durch."""
        print(f"\n🌐 Analysiere IP-Adresse: {ip}")
        
        # Firewall-Erkennung
        firewall_results = self.run_firewall_detection(ip, full_scan=True)
        detected_firewalls = firewall_results.get('detected_firewalls', [])
        print(f"  - Erkannte Firewalls: {len(detected_firewalls)}")
        if detected_firewalls:
            print(f"    {', '.join(detected_firewalls)}")
        
        # Reverse-DNS
        reverse_dns = self.dns_prober.reverse_dns_lookup(ip)
        if reverse_dns.get('hostnames'):
            print(f"  - Reverse-DNS: {reverse_dns['hostnames']}")
    
    def _run_url_analysis(self, url: str):
        """Führt URL-spezifische Analyse durch."""
        print(f"\n🔗 Analysiere URL: {url}")
        
        # Common-Paths-Scan
        paths_results = self.run_paths_scan(url, mode='intelligent')
        found_paths = paths_results.get('combined_results', {}).get('total_found', 0)
        print(f"  - Gefundene Pfade: {found_paths}")
        
        # Extrahiere Domain für DNS-Analyse
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if domain:
            print(f"  - Extrahiere Domain für DNS-Analyse: {domain}")
            dns_results = self.run_dns_analysis(domain)
            print(f"  - DNS-Server getestet: {dns_results['summary']['total_queries']}")
    
    def _create_analysis_summary(self, duration: float) -> Dict:
        """Erstellt eine Zusammenfassung der Analyse."""
        summary = {
            'analysis_duration': duration,
            'timestamp': datetime.now().isoformat(),
            'tests_performed': [],
            'key_findings': {},
            'risk_assessment': 'unknown'
        }
        
        # DNS-Analyse
        if 'dns_analysis' in self.results:
            dns_summary = self.results['dns_analysis']['summary']
            summary['tests_performed'].append('dns_analysis')
            summary['key_findings']['dns'] = {
                'blocked_queries': dns_summary['blocked'],
                'firewall_detected': dns_summary['firewall_detected'],
                'avg_response_time': dns_summary['avg_response_time']
            }
        
        # DNS-Leak-Test
        if 'dns_leak_test' in self.results:
            leak_summary = self.results['dns_leak_test']['summary']
            summary['tests_performed'].append('dns_leak_test')
            summary['key_findings']['dns_leaks'] = {
                'leaks_found': leak_summary['leaks_found'],
                'risk_level': leak_summary['risk_level']
            }
        
        # Firewall-Erkennung
        if 'firewall_detection' in self.results:
            firewall_data = self.results['firewall_detection']
            summary['tests_performed'].append('firewall_detection')
            summary['key_findings']['firewall'] = {
                'detected_firewalls': firewall_data.get('detected_firewalls', []),
                'firewall_indicators': firewall_data.get('firewall_indicators', [])
            }
        
        # Paths-Scan
        if 'paths_scan' in self.results:
            paths_data = self.results['paths_scan']
            summary['tests_performed'].append('paths_scan')
            if 'combined_results' in paths_data:
                combined = paths_data['combined_results']
                summary['key_findings']['paths'] = {
                    'total_found': combined.get('total_found', 0),
                    'categories': list(combined.get('path_categories', {}).keys())
                }
        
        # Risikobewertung
        summary['risk_assessment'] = self._assess_overall_risk()
        
        return summary
    
    def _assess_overall_risk(self) -> str:
        """Bewertet das Gesamtrisiko."""
        risk_factors = []
        
        # DNS-Risiko
        if 'dns_analysis' in self.results:
            dns_blocked = self.results['dns_analysis']['summary']['blocked']
            if dns_blocked > 0:
                risk_factors.append('dns_blocking')
        
        # DNS-Leak-Risiko
        if 'dns_leak_test' in self.results:
            leak_risk = self.results['dns_leak_test']['summary']['risk_level']
            if leak_risk in ['medium', 'high']:
                risk_factors.append(f'dns_leak_{leak_risk}')
        
        # Firewall-Risiko
        if 'firewall_detection' in self.results:
            firewalls = self.results['firewall_detection'].get('detected_firewalls', [])
            if len(firewalls) > 2:
                risk_factors.append('multiple_firewalls')
        
        # Paths-Risiko
        if 'paths_scan' in self.results:
            paths_data = self.results['paths_scan']
            if 'combined_results' in paths_data:
                found_paths = paths_data['combined_results'].get('total_found', 0)
                if found_paths > 30:
                    risk_factors.append('large_attack_surface')
        
        # Bestimme Gesamtrisiko
        if len(risk_factors) >= 3:
            return 'high'
        elif len(risk_factors) >= 1:
            return 'medium'
        else:
            return 'low'
    
    def generate_report(self, output_format: str = 'text') -> str:
        """Generiert einen Bericht."""
        if output_format == 'json':
            return json.dumps(self.results, indent=2, ensure_ascii=False)
        
        # Text-Bericht
        report = []
        report.append("=" * 80)
        report.append("NETZWERK-HEURISTIK-BERICHT")
        report.append(f"Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append("")
        
        # Zusammenfassung
        if 'analysis_summary' in self.results:
            summary = self.results['analysis_summary']
            report.append("ZUSAMMENFASSUNG:")
            report.append(f"  - Analysedauer: {summary['analysis_duration']:.2f} Sekunden")
            report.append(f"  - Durchgeführte Tests: {', '.join(summary['tests_performed'])}")
            report.append(f"  - Gesamtrisiko: {summary['risk_assessment'].upper()}")
            report.append("")
        
        # DNS-Analyse
        if 'dns_analysis' in self.results:
            dns_summary = self.results['dns_analysis']['summary']
            report.append("DNS-ANALYSE:")
            report.append(f"  - Getestete DNS-Server: {dns_summary['total_queries']}")
            report.append(f"  - Blockierte Anfragen: {dns_summary['blocked']}")
            report.append(f"  - Firewall erkannt: {'Ja' if dns_summary['firewall_detected'] > 0 else 'Nein'}")
            report.append("")
        
        # DNS-Leak-Test
        if 'dns_leak_test' in self.results:
            leak_summary = self.results['dns_leak_test']['summary']
            report.append("DNS-LEAK-TEST:")
            report.append(f"  - Gefundene Leaks: {leak_summary['leaks_found']}")
            report.append(f"  - Risikostufe: {leak_summary['risk_level'].upper()}")
            report.append("")
        
        # Firewall-Erkennung
        if 'firewall_detection' in self.results:
            firewall_data = self.results['firewall_detection']
            detected = firewall_data.get('detected_firewalls', [])
            report.append("FIREWALL-ERKENNUNG:")
            report.append(f"  - Erkannte Firewalls: {len(detected)}")
            if detected:
                report.append(f"  - Firewalls: {', '.join(detected)}")
            report.append("")
        
        # Paths-Scan
        if 'paths_scan' in self.results:
            paths_data = self.results['paths_scan']
            if 'combined_results' in paths_data:
                combined = paths_data['combined_results']
                report.append("COMMON-PATHS-SCAN:")
                report.append(f"  - Gefundene Pfade: {combined.get('total_found', 0)}")
                if 'path_categories' in combined:
                    categories = combined['path_categories']
                    for category, paths in categories.items():
                        report.append(f"  - {category.title()}: {len(paths)} Pfade")
                report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results(self, filename: str = None):
        """Speichert alle Ergebnisse."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_heuristics_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse gespeichert: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(
        description='Netzwerk-Heuristiken Suite - DNS-Probing, Leak-Tests, Firewall-Erkennung',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # Vollständige Analyse eines Domain-Namens
  python network_heuristics.py example.com
  
  # IP-Adresse analysieren
  python network_heuristics.py 192.168.1.1
  
  # URL analysieren
  python network_heuristics.py https://example.com
  
  # Nur DNS-Analyse
  python network_heuristics.py example.com --dns-only
  
  # Bericht generieren
  python network_heuristics.py example.com --report
        """
    )
    
    parser.add_argument('target', help='Ziel (Domain, IP oder URL)')
    parser.add_argument('-m', '--mode', 
                       choices=['full', 'dns', 'firewall', 'paths', 'leak'],
                       default='full', help='Analyse-Modus')
    parser.add_argument('--dns-only', action='store_true', help='Nur DNS-Analyse')
    parser.add_argument('--firewall-only', action='store_true', help='Nur Firewall-Erkennung')
    parser.add_argument('--paths-only', action='store_true', help='Nur Paths-Scan')
    parser.add_argument('--leak-only', action='store_true', help='Nur DNS-Leak-Test')
    parser.add_argument('--report', action='store_true', help='Bericht generieren')
    parser.add_argument('-o', '--output', help='Ausgabedatei für Ergebnisse')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Ausgabeformat für Bericht')
    
    args = parser.parse_args()
    
    # Erstelle Suite
    suite = NetworkHeuristicsSuite()
    
    print("🚀 Netzwerk-Heuristiken Suite gestartet")
    print(f"Ziel: {args.target}")
    print(f"Modus: {args.mode}")
    print("-" * 60)
    
    try:
        # Führe Analyse durch
        if args.dns_only or args.mode == 'dns':
            results = suite.run_dns_analysis(args.target, full_scan=True)
        elif args.firewall_only or args.mode == 'firewall':
            results = suite.run_firewall_detection(args.target, full_scan=True)
        elif args.paths_only or args.mode == 'paths':
            results = suite.run_paths_scan(args.target, mode='intelligent')
        elif args.leak_only or args.mode == 'leak':
            results = suite.run_dns_leak_test(f"target_{args.target}")
        else:
            # Vollständige Analyse
            results = suite.run_comprehensive_analysis(args.target)
        
        # Bericht generieren
        if args.report:
            report = suite.generate_report(args.format)
            print("\n" + report)
            
            # Bericht auch in Datei speichern
            report_filename = f"network_heuristics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\nBericht gespeichert: {report_filename}")
        
        # Ergebnisse speichern
        if args.output:
            suite.save_results(args.output)
        else:
            suite.save_results()
        
        print("\n✅ Analyse abgeschlossen!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Analyse durch Benutzer abgebrochen")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fehler während der Analyse: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()