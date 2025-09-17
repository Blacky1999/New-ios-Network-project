#!/usr/bin/env python3
"""
Demo-Script für Netzwerk-Heuristiken Suite
Zeigt die Funktionalität aller Tools anhand von Beispielen.
"""

import sys
import os
from datetime import datetime

# Füge den aktuellen Pfad zu Python-Path hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_probing import DNSProbing
from dns_leak_test import DNSLeakTester
from firewall_detector import FirewallDetector
from common_paths_scanner import CommonPathsScanner

class NetworkHeuristicsDemo:
    def __init__(self):
        self.dns_prober = DNSProbing()
        self.dns_leak_tester = DNSLeakTester()
        self.firewall_detector = FirewallDetector()
        self.paths_scanner = CommonPathsScanner()
        
    def demo_dns_probing(self):
        """Demonstration des DNS-Probing Tools."""
        print("🎯 DNS-Probing Demo")
        print("=" * 50)
        
        # Testdomain
        test_domain = "google.com"
        print(f"Teste DNS-Probing für: {test_domain}")
        
        try:
            # Führe DNS-Analyse durch
            results = self.dns_prober.probe_all_servers(test_domain, ['A', 'AAAA'])
            
            print(f"Ergebnisse für {test_domain}:")
            print(f"  - Getestete DNS-Server: {results['summary']['total_queries']}")
            print(f"  - Erfolgreiche Anfragen: {results['summary']['successful']}")
            print(f"  - Blockierte Anfragen: {results['summary']['blocked']}")
            print(f"  - Firewall erkannt: {results['summary']['firewall_detected']}")
            print(f"  - Durchschnittliche Antwortzeit: {results['summary']['avg_response_time']}s")
            
            # Zeige einige DNS-Server-Ergebnisse
            if results['results']:
                print("\n  Beispiel-DNS-Server-Ergebnisse:")
                for i, server_result in enumerate(results['results'][:3]):
                    server = server_result['server']
                    answers = len(server_result.get('answers', []))
                    error = server_result.get('error', 'Kein Fehler')
                    print(f"    {server}: {answers} Antworten, Status: {error if error else 'OK'}")
            
            # DNS-Hijacking-Test
            print(f"\n  Führe DNS-Hijacking-Test durch...")
            hijack_results = self.dns_prober.detect_dns_hijacking(test_domain)
            print(f"    Hijacking erkannt: {hijack_results['hijacking_detected']}")
            
        except Exception as e:
            print(f"Fehler bei DNS-Probing: {e}")
        
        print()
    
    def demo_dns_leak_test(self):
        """Demonstration des DNS-Leak-Test Tools."""
        print("🎯 DNS-Leak-Test Demo")
        print("=" * 50)
        
        test_name = f"demo_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"Führe DNS-Leak-Test durch: {test_name}")
        
        try:
            # Führe DNS-Leak-Test durch
            results = self.dns_leak_tester.test_dns_leak(test_name)
            
            print("Ergebnisse:")
            print(f"  - Test-Name: {results['test_name']}")
            print(f"  - Zeitstempel: {results['timestamp']}")
            print(f"  - Aktuelle DNS-Server: {results['current_dns_servers']}")
            print(f"  - Gefundene Leaks: {results['summary']['leaks_found']}")
            print(f"  - Risikostufe: {results['summary']['risk_level'].upper()}")
            print(f"  - Durchgeführte Tests: {results['summary']['total_tests']}")
            
            # Zeige Details zu gefundenen Leaks
            if results['leaks_detected']:
                print(f"\n  Gefundene DNS-Leaks:")
                for leak in results['leaks_detected']:
                    leak_type = leak.get('type', 'Unknown')
                    reason = leak.get('reason', 'No reason')
                    print(f"    - {leak_type}: {reason}")
            else:
                print(f"\n  ✅ Keine DNS-Leaks gefunden!")
            
        except Exception as e:
            print(f"Fehler bei DNS-Leak-Test: {e}")
        
        print()
    
    def demo_firewall_detection(self):
        """Demonstration des Firewall-Detection Tools."""
        print("🎯 Firewall-Detection Demo")
        print("=" * 50)
        
        # Verwende localhost für Demo
        test_target = "127.0.0.1"
        print(f"Teste Firewall-Detection für: {test_target}")
        
        try:
            # Führe Firewall-Erkennung durch
            results = self.firewall_detector.detect_firewall_by_response(test_target)
            
            print("Ergebnisse:")
            print(f"  - Ziel: {results['target']}")
            print(f"  - Zeitstempel: {results['timestamp']}")
            print(f"  - Erkannte Firewalls: {len(results.get('detected_firewalls', []))}")
            
            if results.get('detected_firewalls'):
                for firewall in results['detected_firewalls']:
                    print(f"    - {firewall}")
            
            # System-Firewall erkennen
            print(f"\n  System-Firewall-Erkennung:")
            system_results = self.firewall_detector.detect_system_firewall()
            detected_system_firewalls = system_results.get('detected_firewalls', [])
            print(f"    Erkannte System-Firewalls: {len(detected_system_firewalls)}")
            
            if detected_system_firewalls:
                for fw in detected_system_firewalls:
                    print(f"      - {fw}")
                    if fw in system_results.get('firewall_status', {}):
                        status = system_results['firewall_status'][fw]
                        print(f"        Status: {'Aktiv' if status.get('active') else 'Inaktiv'}")
            
        except Exception as e:
            print(f"Fehler bei Firewall-Detection: {e}")
        
        print()
    
    def demo_paths_scanner(self):
        """Demonstration des Common-Paths-Scanners."""
        print("🎯 Common-Paths-Scanner Demo")
        print("=" * 50)
        
        # Verwende eine bekannte Test-URL
        test_url = "https://httpbin.org"
        print(f"Teste Common-Paths-Scanner für: {test_url}")
        print("Hinweis: Dies ist eine Demo mit einer öffentlichen Test-API")
        
        try:
            # Führe intelligenten Scan durch
            results = self.paths_scanner.intelligent_scan(test_url)
            
            print("Ergebnisse:")
            print(f"  - Basis-URL: {results['base_url']}")
            print(f"  - Zeitstempel: {results['timestamp']}")
            
            if 'combined_results' in results:
                combined = results['combined_results']
                print(f"  - Gefundene Pfade: {combined.get('total_found', 0)}")
                
                if 'path_categories' in combined:
                    categories = combined['path_categories']
                    print(f"  - Pfad-Kategorien:")
                    for category, paths in categories.items():
                        print(f"    - {category.title()}: {len(paths)} Pfade")
            
            # Zeige Intelligence-Analyse
            if 'intelligence_analysis' in results:
                analysis = results['intelligence_analysis']
                print(f"\n  Intelligente Analyse:")
                print(f"    - Angriffsoberfläche: {analysis.get('attack_surface_assessment', 'unknown')}")
                print(f"    - Sicherheitsreife: {analysis.get('security_maturity', 'unknown')}")
                
                if analysis.get('recommended_focus_areas'):
                    print(f"    - Empfohlene Fokusbereiche: {', '.join(analysis['recommended_focus_areas'])}")
            
        except Exception as e:
            print(f"Fehler bei Paths-Scanner: {e}")
        
        print()
    
    def run_all_demos(self):
        """Führt alle Demos aus."""
        print("🚀 Netzwerk-Heuristiken Suite - Demo")
        print("=" * 60)
        print(f"Gestartet: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print()
        
        # Führe alle Demos durch
        self.demo_dns_probing()
        self.demo_dns_leak_test()
        self.demo_firewall_detection()
        self.demo_paths_scanner()
        
        print("=" * 60)
        print("✅ Demo abgeschlossen!")
        print(f"Beendet: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print()
        print("📚 Nächste Schritte:")
        print("  1. Lesen Sie die README.md für detaillierte Dokumentation")
        print("  2. Testen Sie die Tools mit Ihren eigenen Zielen")
        print("  3. Verwenden Sie die Master-Suite für umfassende Analysen")
        print()
        print("🔧 Beispiel für Master-Suite:")
        print("  python3 network_heuristics.py example.com --report")
        print()

def main():
    """Hauptfunktion für Demo."""
    print("🧪 Netzwerk-Heuristiken Suite - Demo")
    print("Dieses Script demonstriert alle verfügbaren Tools.")
    print()
    
    # Erstelle Demo-Instanz
    demo = NetworkHeuristicsDemo()
    
    # Frage nach Bestätigung
    response = input("Möchten Sie die Demo starten? (j/n): ").lower().strip()
    if response in ['j', 'ja', 'y', 'yes']:
        demo.run_all_demos()
    else:
        print("Demo abgebrochen.")
        print("Verwenden Sie 'python3 network_heuristics.py --help' für Hilfe.")

if __name__ == '__main__':
    main()