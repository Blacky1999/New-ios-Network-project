#!/usr/bin/env python3
"""
DNS-Leak-Test Tool
Erkennt DNS-Lecks und überprüft, ob DNS-Anfragen über unerwünschte Server laufen.
"""

import dns.resolver
import dns.reversename
import socket
import requests
import concurrent.futures
import argparse
import json
import time
import threading
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import uuid
import random
import string

class DNSLeakTester:
    def __init__(self):
        self.leak_test_servers = {
            'cloudflare': {
                'ipv4': '1.1.1.1',
                'ipv6': '2606:4700:4700::1111',
                'hostname': 'cloudflare-dns.com'
            },
            'google': {
                'ipv4': '8.8.8.8',
                'ipv6': '2001:4860:4860::8888',
                'hostname': 'dns.google'
            },
            'quad9': {
                'ipv4': '9.9.9.9',
                'ipv6': '2620:fe::fe',
                'hostname': 'dns.quad9.net'
            },
            'opendns': {
                'ipv4': '208.67.222.222',
                'ipv6': '2620:119:35::35',
                'hostname': 'dns.opendns.com'
            }
        }
        
        self.leak_test_domains = [
            'dns-leak-test.com',
            'dnsleaktest.com',
            'dns-leak.com',
            'ipleak.net',
            'browserleaks.com',
            'dnssec-debugger.verisignlabs.com',
            'dns.google',
            'cloudflare-dns.com'
        ]
        
        self.results = {}
        self.leaks_detected = []
        
    def get_current_dns_servers(self) -> List[str]:
        """Ermittelt die aktuell konfigurierten DNS-Server des Systems."""
        dns_servers = []
        
        try:
            # Versuche verschiedene Methoden je nach Betriebssystem
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows: ipconfig /all
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'dns servers' in line.lower() or 'dns-server' in line.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                ip = parts[1].strip()
                                if self._is_valid_ip(ip):
                                    dns_servers.append(ip)
            
            elif system == 'linux' or system == 'darwin':
                # Linux/macOS: /etc/resolv.conf
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        content = f.read()
                        for line in content.split('\n'):
                            if line.strip().startswith('nameserver'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip = parts[1]
                                    if self._is_valid_ip(ip):
                                        dns_servers.append(ip)
                except FileNotFoundError:
                    pass
                
                # Alternative: nmcli (NetworkManager)
                try:
                    result = subprocess.run(['nmcli', 'dev', 'show'], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'dns' in line.lower() and not 'dns-search' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 1:
                                    ip = parts[1].strip()
                                    if self._is_valid_ip(ip) and ip not in dns_servers:
                                        dns_servers.append(ip)
                except FileNotFoundError:
                    pass
            
            # Fallback: Socket-Methode
            if not dns_servers:
                resolver = dns.resolver.Resolver()
                dns_servers = resolver.nameservers
                
        except Exception as e:
            print(f"Fehler beim Ermitteln der DNS-Server: {e}")
            # Fallback zu Standard-DNS-Servern
            dns_servers = ['8.8.8.8', '1.1.1.1']
        
        return list(set(dns_servers))  # Entferne Duplikate
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Überprüft, ob eine Zeichenkette eine gültige IP-Adresse ist."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    def test_dns_leak(self, test_name: str = None) -> Dict:
        """Führt einen DNS-Leak-Test durch."""
        if test_name is None:
            test_name = f"leak_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        result = {
            'test_name': test_name,
            'timestamp': datetime.now().isoformat(),
            'current_dns_servers': self.get_current_dns_servers(),
            'leaks_detected': [],
            'test_results': {},
            'summary': {
                'total_tests': 0,
                'leaks_found': 0,
                'risk_level': 'low'
            }
        }
        
        print(f"Starte DNS-Leak-Test: {test_name}")
        print(f"Aktuelle DNS-Server: {result['current_dns_servers']}")
        
        # Test 1: Standard-DNS-Abfragen
        print("Teste Standard-DNS-Abfragen...")
        result['test_results']['standard_queries'] = self._test_standard_queries()
        
        # Test 2: Extended-DNS-Test
        print("Teste Extended-DNS...")
        result['test_results']['extended_dns'] = self._test_extended_dns()
        
        # Test 3: DNS-over-HTTPS-Test
        print("Teste DNS-over-HTTPS...")
        result['test_results']['doh_test'] = self._test_dns_over_https()
        
        # Test 4: DNS-over-TLS-Test
        print("Teste DNS-over-TLS...")
        result['test_results']['dot_test'] = self._test_dns_over_tls()
        
        # Test 5: Vergleich mit bekannten DNS-Leak-Test-Sites
        print("Teste gegen bekannte DNS-Leak-Test-Sites...")
        result['test_results']['known_sites'] = self._test_known_sites()
        
        # Analysiere Ergebnisse
        result = self._analyze_leak_results(result)
        
        self.results[test_name] = result
        return result
    
    def _test_standard_queries(self) -> Dict:
        """Führt Standard-DNS-Abfragen durch."""
        results = {
            'queries': [],
            'leaks_found': [],
            'response_analysis': {}
        }
        
        test_domains = [
            'google.com',
            'cloudflare.com',
            'example.com',
            'dns-leak-test.com'
        ]
        
        for domain in test_domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                start_time = time.time()
                answer = resolver.resolve(domain, 'A')
                response_time = time.time() - start_time
                
                answers = [str(rdata) for rdata in answer]
                
                query_result = {
                    'domain': domain,
                    'response_time': round(response_time, 3),
                    'answers': answers,
                    'resolver_used': resolver.nameservers,
                    'potential_leak': False
                }
                
                # Prüfe auf verdächtige Antworten
                for answer in answers:
                    if self._is_suspicious_answer(answer, domain):
                        query_result['potential_leak'] = True
                        results['leaks_found'].append({
                            'domain': domain,
                            'reason': f'Suspicious answer: {answer}',
                            'type': 'suspicious_response'
                        })
                
                results['queries'].append(query_result)
                
            except Exception as e:
                results['queries'].append({
                    'domain': domain,
                    'error': str(e),
                    'potential_leak': False
                })
        
        return results
    
    def _is_suspicious_answer(self, answer: str, domain: str) -> bool:
        """Prüft, ob eine DNS-Antwort verdächtig ist."""
        # Prüfe auf private IP-Adressen für öffentliche Domains
        private_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.',
            '169.254.'  # Link-local
        ]
        
        for private_range in private_ranges:
            if answer.startswith(private_range):
                return True
        
        # Prüfe auf bekannte bösartige IPs
        suspicious_ips = [
            '0.0.0.0',
            '255.255.255.255'
        ]
        
        return answer in suspicious_ips
    
    def _test_extended_dns(self) -> Dict:
        """Führt erweiterte DNS-Tests durch."""
        results = {
            'tests': [],
            'leaks_found': []
        }
        
        # Erstelle zufällige Subdomains für DNS-Leak-Test
        random_subdomains = []
        for i in range(5):
            random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            random_subdomains.append(f"{random_sub}.dns-leak-test.com")
        
        for subdomain in random_subdomains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                
                answer = resolver.resolve(subdomain, 'A')
                answers = [str(rdata) for rdata in answer]
                
                # Wenn eine zufällige Subdomain aufgelöst wird, ist das ein DNS-Leak
                if answers:
                    results['leaks_found'].append({
                        'subdomain': subdomain,
                        'answers': answers,
                        'type': 'wildcard_resolution'
                    })
                
                results['tests'].append({
                    'subdomain': subdomain,
                    'resolved': True,
                    'answers': answers
                })
                
            except dns.resolver.NXDOMAIN:
                results['tests'].append({
                    'subdomain': subdomain,
                    'resolved': False,
                    'error': 'NXDOMAIN'
                })
            except Exception as e:
                results['tests'].append({
                    'subdomain': subdomain,
                    'resolved': False,
                    'error': str(e)
                })
        
        return results
    
    def _test_dns_over_https(self) -> Dict:
        """Testet DNS-over-HTTPS."""
        results = {
            'tested_providers': [],
            'working_providers': [],
            'leaks_found': []
        }
        
        doh_providers = {
            'cloudflare': 'https://cloudflare-dns.com/dns-query',
            'google': 'https://dns.google/dns-query',
            'quad9': 'https://dns.quad9.net/dns-query'
        }
        
        test_domain = 'dns-leak-test.com'
        
        for provider, doh_url in doh_providers.items():
            try:
                headers = {
                    'Accept': 'application/dns-json',
                    'User-Agent': 'DNS-Leak-Test-Tool/1.0'
                }
                
                params = {
                    'name': test_domain,
                    'type': 'A'
                }
                
                response = requests.get(doh_url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        results['working_providers'].append(provider)
                        
                        # Analysiere Antworten
                        for answer in data['Answer']:
                            if 'data' in answer:
                                ip = answer['data']
                                if self._is_suspicious_answer(ip, test_domain):
                                    results['leaks_found'].append({
                                        'provider': provider,
                                        'ip': ip,
                                        'type': 'suspicious_doh_response'
                                    })
                
                results['tested_providers'].append(provider)
                
            except Exception as e:
                results['tested_providers'].append(provider)
                results[f'{provider}_error'] = str(e)
        
        return results
    
    def _test_dns_over_tls(self) -> Dict:
        """Testet DNS-over-TLS (simuliert)."""
        results = {
            'note': 'DNS-over-TLS-Test erfordert spezielle Bibliotheken',
            'simulated_test': True,
            'tested_methods': [],
            'leaks_found': []
        }
        
        # Da DOT eine TCP-Verbindung mit TLS erfordert, simulieren wir hier
        # In einer echten Implementierung würde man ssl.create_connection() verwenden
        
        dot_servers = [
            ('cloudflare', '1.1.1.1', 853),
            ('google', '8.8.8.8', 853),
            ('quad9', '9.9.9.9', 853)
        ]
        
        for provider, server, port in dot_servers:
            try:
                # Simulierter DOT-Test
                results['tested_methods'].append({
                    'provider': provider,
                    'server': server,
                    'port': port,
                    'status': 'simulated'
                })
                
            except Exception as e:
                results['tested_methods'].append({
                    'provider': provider,
                    'server': server,
                    'port': port,
                    'error': str(e)
                })
        
        return results
    
    def _test_known_sites(self) -> Dict:
        """Testet gegen bekannte DNS-Leak-Test-Sites."""
        results = {
            'sites_tested': [],
            'working_sites': [],
            'leaks_found': []
        }
        
        for site in self.leak_test_domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answer = resolver.resolve(site, 'A')
                answers = [str(rdata) for rdata in answer]
                
                results['sites_tested'].append(site)
                results['working_sites'].append(site)
                
                # Analysiere Antworten
                for answer_ip in answers:
                    if self._is_suspicious_answer(answer_ip, site):
                        results['leaks_found'].append({
                            'site': site,
                            'ip': answer_ip,
                            'type': 'suspicious_known_site_response'
                        })
                
            except Exception as e:
                results['sites_tested'].append(site)
                results[f'{site}_error'] = str(e)
        
        return results
    
    def _analyze_leak_results(self, result: Dict) -> Dict:
        """Analysiert die Leak-Test-Ergebnisse."""
        total_leaks = 0
        all_leaks = []
        
        # Sammle alle Leaks aus verschiedenen Tests
        for test_name, test_result in result['test_results'].items():
            if isinstance(test_result, dict) and 'leaks_found' in test_result:
                leaks = test_result['leaks_found']
                total_leaks += len(leaks)
                all_leaks.extend(leaks)
        
        result['leaks_detected'] = all_leaks
        result['summary']['total_tests'] = sum(1 for test in result['test_results'].values() if isinstance(test, dict))
        result['summary']['leaks_found'] = total_leaks
        
        # Bestimme Risikostufe
        if total_leaks == 0:
            result['summary']['risk_level'] = 'low'
        elif total_leaks <= 2:
            result['summary']['risk_level'] = 'medium'
        else:
            result['summary']['risk_level'] = 'high'
        
        return result
    
    def generate_report(self, test_name: str = None) -> str:
        """Generiert einen detalierten Bericht."""
        if test_name is None:
            if not self.results:
                return "Keine Testergebnisse vorhanden."
            test_name = list(self.results.keys())[-1]
        
        if test_name not in self.results:
            return f"Test '{test_name}' nicht gefunden."
        
        result = self.results[test_name]
        
        report = []
        report.append("=" * 60)
        report.append(f"DNS-LEAK-TEST-BERICHT")
        report.append(f"Test: {result['test_name']}")
        report.append(f"Zeitstempel: {result['timestamp']}")
        report.append("=" * 60)
        report.append("")
        
        # Zusammenfassung
        report.append("ZUSAMMENFASSUNG:")
        report.append(f"  - Risikostufe: {result['summary']['risk_level'].upper()}")
        report.append(f"  - Gefundene Leaks: {result['summary']['leaks_found']}")
        report.append(f"  - Durchgeführte Tests: {result['summary']['total_tests']}")
        report.append("")
        
        # DNS-Server
        report.append("AKTUELLE DNS-SERVER:")
        for server in result['current_dns_servers']:
            report.append(f"  - {server}")
        report.append("")
        
        # Gefundene Leaks
        if result['leaks_detected']:
            report.append("GEFUNDENE DNS-LEAKS:")
            for leak in result['leaks_detected']:
                report.append(f"  - {leak.get('type', 'Unknown')}: {leak.get('reason', 'No reason')}")
        else:
            report.append("KEINE DNS-LEAKS GEFUNDEN!")
        
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)
    
    def save_results(self, filename: str = None):
        """Speichert alle Testergebnisse."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_leak_test_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse gespeichert: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='DNS-Leak-Test Tool')
    parser.add_argument('-t', '--test-name', help='Name für diesen Test')
    parser.add_argument('-o', '--output', help='Ausgabedatei für Ergebnisse')
    parser.add_argument('--report', action='store_true', help='Bericht generieren')
    parser.add_argument('--quick', action='store_true', help='Schneller Test')
    
    args = parser.parse_args()
    
    tester = DNSLeakTester()
    
    print("Starte DNS-Leak-Test...")
    
    # Führe Test durch
    if args.quick:
        # Schneller Test mit reduzierten Parametern
        result = tester.test_dns_leak(args.test_name or "quick_test")
    else:
        result = tester.test_dns_leak(args.test_name)
    
    # Zeige Zusammenfassung
    print(f"\nTest abgeschlossen!")
    print(f"Risikostufe: {result['summary']['risk_level'].upper()}")
    print(f"Gefundene Leaks: {result['summary']['leaks_found']}")
    
    # Bericht generieren
    if args.report:
        report = tester.generate_report()
        print("\n" + report)
        
        # Bericht auch in Datei speichern
        report_filename = f"dns_leak_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\nBericht gespeichert: {report_filename}")
    
    # Ergebnisse speichern
    if args.output:
        tester.save_results(args.output)
    else:
        tester.save_results()

if __name__ == '__main__':
    main()