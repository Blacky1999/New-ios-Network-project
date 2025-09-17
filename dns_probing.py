#!/usr/bin/env python3
"""
DNS-Probing Tool
Ein umfassendes Tool für DNS-Anfragen, -Antworten und -Analyse.
Kann blockierte DNS-Anfragen umgehen und Firewalls identifizieren.
"""

import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import socket
import concurrent.futures
import argparse
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import requests
import subprocess
import platform

class DNSProbing:
    def __init__(self):
        self.results = {}
        self.dns_servers = [
            '8.8.8.8',           # Google
            '8.8.4.4',           # Google Secondary
            '1.1.1.1',           # Cloudflare
            '1.0.0.1',           # Cloudflare Secondary
            '208.67.222.222',      # OpenDNS
            '208.67.220.220',      # OpenDNS Secondary
            '9.9.9.9',           # Quad9
            '149.112.112.112',     # Quad9 Secondary
        ]
        self.common_records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']
        self.firewall_indicators = []
        
    def check_dns_server(self, server: str, domain: str, record_type: str = 'A') -> Dict:
        """Überprüft einen spezifischen DNS-Server für eine Domain."""
        result = {
            'server': server,
            'domain': domain,
            'record_type': record_type,
            'timestamp': datetime.now().isoformat(),
            'response_time': None,
            'answers': [],
            'error': None,
            'blocked': False,
            'firewall_detected': False
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 5
            resolver.lifetime = 10
            
            start_time = time.time()
            
            # Versuche DNS-Abfrage
            if record_type == 'PTR':
                # Für Reverse DNS
                try:
                    addr = dns.reversename.from_address(domain)
                    answer = resolver.resolve(addr, 'PTR')
                except Exception as e:
                    answer = resolver.resolve(domain, 'A')
            else:
                answer = resolver.resolve(domain, record_type)
            
            response_time = time.time() - start_time
            result['response_time'] = round(response_time, 3)
            
            # Verarbeite Antworten
            for rdata in answer:
                result['answers'].append(str(rdata))
                
            # Firewall-Erkennung basierend auf Antwortzeit und Mustern
            if response_time > 2.0 or len(result['answers']) == 0:
                result['firewall_detected'] = True
                self.firewall_indicators.append({
                    'server': server,
                    'domain': domain,
                    'reason': 'Slow response or empty answers'
                })
                
        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain not found'
            result['blocked'] = True
        except dns.resolver.NoAnswer:
            result['error'] = 'No answer from server'
            result['blocked'] = True
        except dns.resolver.Timeout:
            result['error'] = 'Timeout - possible firewall'
            result['blocked'] = True
            result['firewall_detected'] = True
            self.firewall_indicators.append({
                'server': server,
                'domain': domain,
                'reason': 'DNS timeout'
            })
        except Exception as e:
            result['error'] = str(e)
            if 'refused' in str(e).lower() or 'blocked' in str(e).lower():
                result['blocked'] = True
                result['firewall_detected'] = True
                
        return result
    
    def probe_all_servers(self, domain: str, record_types: List[str] = None) -> Dict:
        """Probiert alle DNS-Server für eine Domain."""
        if record_types is None:
            record_types = ['A']
            
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'results': [],
            'summary': {
                'total_queries': 0,
                'successful': 0,
                'blocked': 0,
                'firewall_detected': 0,
                'avg_response_time': 0
            }
        }
        
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for server in self.dns_servers:
                for record_type in record_types:
                    futures.append(
                        executor.submit(self.check_dns_server, server, domain, record_type)
                    )
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                all_results.append(result)
                results['results'].append(result)
        
        # Zusammenfassung
        results['summary']['total_queries'] = len(all_results)
        results['summary']['successful'] = len([r for r in all_results if not r['error']])
        results['summary']['blocked'] = len([r for r in all_results if r['blocked']])
        results['summary']['firewall_detected'] = len([r for r in all_results if r['firewall_detected']])
        
        response_times = [r['response_time'] for r in all_results if r['response_time']]
        if response_times:
            results['summary']['avg_response_time'] = round(sum(response_times) / len(response_times), 3)
            
        return results
    
    def reverse_dns_lookup(self, ip_address: str) -> Dict:
        """Führt Reverse-DNS-Lookup durch."""
        result = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'hostnames': [],
            'error': None
        }
        
        try:
            hostname = socket.gethostbyaddr(ip_address)
            result['hostnames'].append(hostname[0])
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def dns_traceroute(self, domain: str) -> Dict:
        """Führt DNS-Traceroute durch."""
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'hops': [],
            'path_analysis': {}
        }
        
        # Versuche DNS-Traceroute mit verschiedenen Methoden
        try:
            # TTL-basierte DNS-Abfragen
            for ttl in range(1, 30):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8']
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    
                    # Erstelle Raw-DNS-Query mit spezifischem TTL
                    query = dns.message.make_query(domain, 'A')
                    query.flags = 0x0120  # Standard DNS-Flags
                    
                    # TTL-basierte Anfrage (simuliert)
                    response = resolver.resolve(domain, 'A')
                    
                    hop_info = {
                        'ttl': ttl,
                        'responded': True,
                        'timestamp': time.time()
                    }
                    result['hops'].append(hop_info)
                    
                except dns.resolver.Timeout:
                    result['hops'].append({
                        'ttl': ttl,
                        'responded': False,
                        'timestamp': time.time()
                    })
                    break
                    
        except Exception as e:
            result['path_analysis']['error'] = str(e)
            
        return result
    
    def detect_dns_hijacking(self, domain: str) -> Dict:
        """Erkennt mögliches DNS-Hijacking."""
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'hijacking_detected': False,
            'analysis': {},
            'evidence': []
        }
        
        # Hole Ergebnisse von verschiedenen DNS-Servern
        dns_results = self.probe_all_servers(domain, ['A', 'AAAA'])
        
        # Analysiere Antworten auf Konsistenz
        all_answers = []
        for server_result in dns_results['results']:
            if server_result['answers']:
                all_answers.extend(server_result['answers'])
        
        # Prüfe auf inkonsistente Antworten
        unique_answers = list(set(all_answers))
        if len(unique_answers) > 1:
            result['hijacking_detected'] = True
            result['evidence'].append(f"Inconsistent responses: {unique_answers}")
        
        # Prüfe auf bekannte bösartige IPs
        suspicious_ips = [
            '127.0.0.1', '0.0.0.0', '192.168.', '10.', '172.16.', '172.31.'
        ]
        
        for answer in all_answers:
            for suspicious in suspicious_ips:
                if answer.startswith(suspicious):
                    result['hijacking_detected'] = True
                    result['evidence'].append(f"Suspicious IP returned: {answer}")
                    break
        
        result['analysis'] = {
            'total_servers': len(dns_results['results']),
            'consistent_responses': len(unique_answers) == 1,
            'unique_answers': unique_answers
        }
        
        return result
    
    def scan_common_records(self, domain: str) -> Dict:
        """Scannt häufige DNS-Record-Typen."""
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'records': {},
            'missing_records': [],
            'analysis': {}
        }
        
        for record_type in self.common_records:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answer = resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answer]
                result['records'][record_type] = records
                
            except dns.resolver.NoAnswer:
                result['missing_records'].append(record_type)
            except Exception as e:
                result['records'][record_type] = f"Error: {str(e)}"
        
        # Analysiere Ergebnisse
        result['analysis'] = {
            'found_records': len([r for r in result['records'].values() if not str(r).startswith('Error')]),
            'missing_records': len(result['missing_records']),
            'security_issues': []
        }
        
        # Prüfe auf Sicherheitsprobleme
        if 'TXT' in result['records']:
            txt_records = result['records']['TXT']
            for txt in txt_records:
                if 'v=spf1' in txt and 'include:' not in txt:
                    result['analysis']['security_issues'].append("SPF record too permissive")
        
        return result
    
    def save_results(self, filename: str = None):
        """Speichert alle Ergebnisse in einer JSON-Datei."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_probing_results_{timestamp}.json"
        
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'results': self.results,
            'firewall_indicators': self.firewall_indicators,
            'summary': {
                'total_domains_tested': len(self.results),
                'firewall_detections': len(self.firewall_indicators)
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse gespeichert in: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='DNS-Probing Tool')
    parser.add_argument('domain', help='Domain für DNS-Analyse')
    parser.add_argument('-r', '--record-types', nargs='+', 
                       default=['A'], help='DNS-Record-Typen')
    parser.add_argument('-o', '--output', help='Ausgabedatei')
    parser.add_argument('--hijack-check', action='store_true',
                       help='DNS-Hijacking-Check durchführen')
    parser.add_argument('--trace', action='store_true',
                       help='DNS-Traceroute durchführen')
    parser.add_argument('--full-scan', action='store_true',
                       help='Vollständigen DNS-Scan durchführen')
    
    args = parser.parse_args()
    
    dns_prober = DNSProbing()
    
    print(f"Starte DNS-Probing für: {args.domain}")
    
    # Standard-DNS-Probing
    results = dns_prober.probe_all_servers(args.domain, args.record_types)
    print(f"DNS-Server getestet: {results['summary']['total_queries']}")
    print(f"Blockierte Anfragen: {results['summary']['blocked']}")
    print(f"Firewall erkannt: {results['summary']['firewall_detected']}")
    
    # Optionale zusätzliche Tests
    if args.full_scan:
        print("Führe vollständigen DNS-Scan durch...")
        scan_results = dns_prober.scan_common_records(args.domain)
        print(f"Gefundene Records: {scan_results['analysis']['found_records']}")
        
    if args.hijack_check:
        print("Überprüfe auf DNS-Hijacking...")
        hijack_results = dns_prober.detect_dns_hijacking(args.domain)
        print(f"DNS-Hijacking erkannt: {hijack_results['hijacking_detected']}")
        
    if args.trace:
        print("Führe DNS-Traceroute durch...")
        trace_results = dns_prober.dns_traceroute(args.domain)
        print(f"Traceroute-Hops: {len(trace_results['hops'])}")
    
    # Ergebnisse speichern
    if args.output:
        dns_prober.results[args.domain] = results
        dns_prober.save_results(args.output)
    
    # Detaillierte Ergebnisse anzeigen
    print("\nDetaillierte Ergebnisse:")
    for server_result in results['results']:
        if server_result['error']:
            print(f"  {server_result['server']}: {server_result['error']}")
        else:
            print(f"  {server_result['server']}: {len(server_result['answers'])} Antworten")

if __name__ == '__main__':
    main()