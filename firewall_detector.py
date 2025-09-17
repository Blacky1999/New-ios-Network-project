#!/usr/bin/env python3
"""
Firewall-Detection- und Netzwerkanalyse-Tool
Erkennt Firewalls, Analysiert Netzwerkkonfigurationen und umgeht Blockaden.
"""

import socket
import subprocess
import platform
import concurrent.futures
import argparse
import json
import time
import struct
import random
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import ipaddress
import re

class FirewallDetector:
    def __init__(self):
        self.firewall_signatures = {
            'iptables': {
                'name': 'iptables/Linux Firewall',
                'indicators': ['iptables', 'netfilter', 'ACCEPT', 'DROP', 'REJECT'],
                'ports': [22, 80, 443, 8080, 53, 123]
            },
            'windows_firewall': {
                'name': 'Windows Firewall',
                'indicators': ['Windows Firewall', 'wf.msc', 'netsh firewall', 'Domain,Private,Public'],
                'ports': [135, 139, 445, 3389]
            },
            'pfsense': {
                'name': 'pfSense',
                'indicators': ['pfSense', 'pf', 'pfsense', 'lighttpd'],
                'ports': [80, 443, 22, 8080]
            },
            'cisco_asa': {
                'name': 'Cisco ASA',
                'indicators': ['Cisco Adaptive Security', 'ASA', 'ciscoasa', 'pix'],
                'ports': [22, 443, 161]
            },
            'fortinet': {
                'name': 'Fortinet FortiGate',
                'indicators': ['FortiGate', 'Fortinet', 'fortios', 'FGT'],
                'ports': [80, 443, 22]
            },
            'checkpoint': {
                'name': 'Check Point',
                'indicators': ['Check Point', 'fw', 'cpuse', 'gaia'],
                'ports': [80, 443, 22, 18184]
            },
            'sophos': {
                'name': 'Sophos XG',
                'indicators': ['Sophos', 'XG', 'sophos', 'UTM'],
                'ports': [80, 443, 22, 4116]
            },
            'sonicwall': {
                'name': 'SonicWall',
                'indicators': ['SonicWall', 'sonic', 'tz', 'nsa'],
                'ports': [80, 443, 22]
            }
        }
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]
        self.evidence = []
        self.results = {}
        
    def detect_firewall_by_response(self, target: str, port: int = 80) -> Dict:
        """Erkennt Firewalls anhand von Antwortmustern."""
        result = {
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'detected_firewalls': [],
            'response_analysis': {},
            'evidence': []
        }
        
        try:
            # Teste verschiedene Verbindungsmethoden
            tests = [
                ('tcp_connect', self._test_tcp_connect),
                ('http_probe', self._test_http_probe),
                ('icmp_probe', self._test_icmp_probe),
                ('udp_probe', self._test_udp_probe)
            ]
            
            for test_name, test_func in tests:
                try:
                    test_result = test_func(target, port)
                    result['response_analysis'][test_name] = test_result
                    
                    # Analysiere auf Firewall-Muster
                    firewall_detected = self._analyze_firewall_patterns(test_result, test_name)
                    if firewall_detected:
                        result['detected_firewalls'].extend(firewall_detected)
                        
                except Exception as e:
                    result['response_analysis'][test_name] = {'error': str(e)}
            
            # Entferne Duplikate
            result['detected_firewalls'] = list(set(result['detected_firewalls']))
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _test_tcp_connect(self, target: str, port: int) -> Dict:
        """Testet TCP-Verbindungen."""
        result = {
            'method': 'tcp_connect',
            'target': target,
            'port': port,
            'connect_time': None,
            'connection_successful': False,
            'blocking_behavior': None
        }
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            connection_result = sock.connect_ex((target, port))
            connect_time = time.time() - start_time
            
            result['connect_time'] = round(connect_time, 3)
            result['connection_successful'] = (connection_result == 0)
            
            # Analysiere Verbindungsverhalten
            if connection_result == 110:  # Connection timed out
                result['blocking_behavior'] = 'timeout'
                result['firewall_indicator'] = 'possible_packet_filter'
            elif connection_result == 111:  # Connection refused
                result['blocking_behavior'] = 'refused'
                result['firewall_indicator'] = 'port_closed_or_blocked'
            elif connection_result == 10060:  # Windows timeout
                result['blocking_behavior'] = 'timeout'
                result['firewall_indicator'] = 'possible_firewall'
            
            sock.close()
            
        except socket.timeout:
            result['blocking_behavior'] = 'timeout'
            result['firewall_indicator'] = 'connection_timeout'
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _test_http_probe(self, target: str, port: int = 80) -> Dict:
        """Testet HTTP/HTTPS-Verbindungen."""
        result = {
            'method': 'http_probe',
            'target': target,
            'port': port,
            'http_response': None,
            'headers': {},
            'firewall_indicators': []
        }
        
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}:{port if port not in [80, 443] else ''}/"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
                
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                
                result['http_response'] = {
                    'protocol': protocol,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.content)
                }
                
                # Analysiere HTTP-Header auf Firewall-Indikatoren
                firewall_indicators = self._analyze_http_headers(response.headers)
                if firewall_indicators:
                    result['firewall_indicators'].extend(firewall_indicators)
                
                break  # Erfolgreiche Verbindung, keine weitere Tests nötig
                
            except requests.exceptions.Timeout:
                result[f'{protocol}_timeout'] = True
                result['firewall_indicators'].append(f'{protocol}_timeout')
            except requests.exceptions.ConnectionError as e:
                result[f'{protocol}_connection_error'] = str(e)
                if 'refused' in str(e).lower():
                    result['firewall_indicators'].append('connection_refused')
            except Exception as e:
                result[f'{protocol}_error'] = str(e)
        
        return result
    
    def _test_icmp_probe(self, target: str) -> Dict:
        """Testet ICMP (Ping)."""
        result = {
            'method': 'icmp_probe',
            'target': target,
            'icmp_available': False,
            'ping_results': {}
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                ping_cmd = ['ping', '-n', '2', '-w', '3000', target]
            else:
                ping_cmd = ['ping', '-c', '2', '-W', '3', target]
            
            ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=10)
            
            result['ping_results'] = {
                'returncode': ping_result.returncode,
                'stdout': ping_result.stdout,
                'stderr': ping_result.stderr
            }
            
            result['icmp_available'] = (ping_result.returncode == 0)
            
            # Analysiere Ping-Ausgabe
            if ping_result.returncode != 0:
                if 'Destination host unreachable' in ping_result.stdout:
                    result['blocking_behavior'] = 'host_unreachable'
                elif 'Request timed out' in ping_result.stdout:
                    result['blocking_behavior'] = 'timeout'
                    result['firewall_indicator'] = 'icmp_blocked'
                elif '100% packet loss' in ping_result.stdout:
                    result['blocking_behavior'] = 'packet_loss'
                    result['firewall_indicator'] = 'packets_dropped'
            
        except subprocess.TimeoutExpired:
            result['ping_timeout'] = True
            result['firewall_indicator'] = 'ping_timeout'
        except Exception as e:
            result['icmp_error'] = str(e)
            
        return result
    
    def _test_udp_probe(self, target: str, port: int = 53) -> Dict:
        """Testet UDP-Verbindungen."""
        result = {
            'method': 'udp_probe',
            'target': target,
            'port': port,
            'udp_successful': False,
            'dns_probe': {}
        }
        
        try:
            # DNS-UDP-Test
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Erstelle einfache DNS-Anfrage
            dns_query = self._create_dns_query(target)
            sock.sendto(dns_query, (target, port))
            
            data, addr = sock.recvfrom(1024)
            result['udp_successful'] = True
            result['dns_probe'] = {
                'response_received': True,
                'response_length': len(data),
                'from_address': addr
            }
            
            sock.close()
            
        except socket.timeout:
            result['udp_timeout'] = True
            result['firewall_indicator'] = 'udp_blocked'
        except Exception as e:
            result['udp_error'] = str(e)
            result['firewall_indicator'] = 'udp_connection_failed'
            
        return result
    
    def _create_dns_query(self, domain: str) -> bytes:
        """Erstellt eine einfache DNS-Anfrage."""
        # Vereinfachte DNS-Anfrage (A-Record)
        transaction_id = b'\x00\x01'
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answer_rrs = b'\x00\x00'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        
        # Domain-Namen encodieren
        query_name = b''
        for part in domain.split('.'):
            query_name += bytes([len(part)]) + part.encode()
        query_name += b'\x00'
        
        query_type = b'\x00\x01'  # A-Record
        query_class = b'\x00\x01'  # IN
        
        return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query_name + query_type + query_class
    
    def _analyze_firewall_patterns(self, test_result: Dict, test_method: str) -> List[str]:
        """Analysiert Testergebnisse auf Firewall-Muster."""
        detected_firewalls = []
        
        # Timeout-basierte Erkennung
        if 'connect_time' in test_result and test_result['connect_time'] and test_result['connect_time'] > 3.0:
            detected_firewalls.append('timeout_based_firewall')
        
        # Verbindungsverhalten
        if 'blocking_behavior' in test_result:
            behavior = test_result['blocking_behavior']
            if behavior == 'timeout':
                detected_firewalls.append('packet_filtering_firewall')
            elif behavior == 'refused':
                detected_firewalls.append('connection_blocking_firewall')
            elif behavior == 'host_unreachable':
                detected_firewalls.append('network_level_firewall')
        
        # HTTP-basierte Erkennung
        if test_method == 'http_probe' and 'http_response' in test_result:
            http_info = test_result['http_response']
            if http_info and 'status_code' in http_info:
                if http_info['status_code'] == 403:
                    detected_firewalls.append('web_application_firewall')
                elif http_info['status_code'] == 407:
                    detected_firewalls.append('proxy_firewall')
        
        return detected_firewalls
    
    def _analyze_http_headers(self, headers: Dict) -> List[str]:
        """Analysiert HTTP-Header auf Firewall-Indikatoren."""
        indicators = []
        
        header_text = str(headers).lower()
        
        # Prüfe auf bekannte Firewall-Header
        firewall_headers = {
            'x-sophos': 'sophos_firewall',
            'x-palo-alto': 'palo_alto_firewall',
            'x-fortigate': 'fortinet_firewall',
            'x-cisco': 'cisco_firewall',
            'x-checkpoint': 'checkpoint_firewall',
            'x-sonicwall': 'sonicwall_firewall',
            'server': 'generic_firewall'
        }
        
        for header, firewall_type in firewall_headers.items():
            if header in header_text:
                indicators.append(firewall_type)
        
        # Prüfe auf generische Firewall-Muster
        if 'firewall' in header_text:
            indicators.append('generic_firewall_detected')
        
        return indicators
    
    def scan_ports(self, target: str, ports: List[int] = None) -> Dict:
        """Scannt Ports und erkennt Firewall-basierte Blockaden."""
        if ports is None:
            ports = self.common_ports
        
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'port_scan': {},
            'firewall_indicators': [],
            'blocked_ports': [],
            'open_ports': [],
            'filtered_ports': []
        }
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                connect_result = sock.connect_ex((target, port))
                
                if connect_result == 0:
                    return {'port': port, 'status': 'open', 'blocked': False}
                elif connect_result == 110:  # Timeout
                    return {'port': port, 'status': 'filtered', 'blocked': True, 'reason': 'timeout'}
                elif connect_result == 111:  # Connection refused
                    return {'port': port, 'status': 'closed', 'blocked': True, 'reason': 'refused'}
                else:
                    return {'port': port, 'status': 'unknown', 'blocked': False, 'error': connect_result}
                
                sock.close()
                
            except socket.timeout:
                return {'port': port, 'status': 'filtered', 'blocked': True, 'reason': 'timeout'}
            except Exception as e:
                return {'port': port, 'status': 'error', 'blocked': False, 'error': str(e)}
        
        # Führe Port-Scan durch
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future in concurrent.futures.as_completed(futures):
                scan_result = future.result()
                port = scan_result['port']
                
                result['port_scan'][port] = scan_result
                
                if scan_result['blocked']:
                    result['blocked_ports'].append(port)
                elif scan_result['status'] == 'open':
                    result['open_ports'].append(port)
                elif scan_result['status'] == 'filtered':
                    result['filtered_ports'].append(port)
        
        # Analysiere auf Firewall-Muster
        if len(result['filtered_ports']) > len(ports) * 0.3:  # >30% gefiltert
            result['firewall_indicators'].append('port_filtering_firewall')
        
        if len(result['blocked_ports']) > len(ports) * 0.5:  # >50% blockiert
            result['firewall_indicators'].append('aggressive_firewall')
        
        return result
    
    def detect_system_firewall(self) -> Dict:
        """Erkennt die auf dem System laufende Firewall."""
        result = {
            'timestamp': datetime.now().isoformat(),
            'system': platform.system(),
            'detected_firewalls': [],
            'firewall_status': {},
            'rules_analysis': {}
        }
        
        system = platform.system().lower()
        
        try:
            if system == 'linux':
                result.update(self._detect_linux_firewall())
            elif system == 'windows':
                result.update(self._detect_windows_firewall())
            elif system == 'darwin':
                result.update(self._detect_macos_firewall())
            else:
                result['error'] = f'Nicht unterstütztes Betriebssystem: {system}'
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _detect_linux_firewall(self) -> Dict:
        """Erkennt Linux-Firewalls (iptables, nftables, firewalld, ufw)."""
        result = {
            'detected_firewalls': [],
            'firewall_status': {},
            'rules_analysis': {}
        }
        
        # iptables-Überprüfung
        try:
            iptables_result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10)
            if iptables_result.returncode == 0 and iptables_result.stdout:
                result['detected_firewalls'].append('iptables')
                result['firewall_status']['iptables'] = {
                    'active': True,
                    'rules_count': len(iptables_result.stdout.split('\n')),
                    'summary': self._analyze_iptables_rules(iptables_result.stdout)
                }
        except:
            pass
        
        # nftables-Überprüfung
        try:
            nft_result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, timeout=10)
            if nft_result.returncode == 0 and nft_result.stdout:
                result['detected_firewalls'].append('nftables')
                result['firewall_status']['nftables'] = {
                    'active': True,
                    'rules_count': len(nft_result.stdout.split('\n'))
                }
        except:
            pass
        
        # firewalld-Überprüfung
        try:
            firewall_cmd_result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=5)
            if firewall_cmd_result.returncode == 0 and 'running' in firewall_cmd_result.stdout.lower():
                result['detected_firewalls'].append('firewalld')
                result['firewall_status']['firewalld'] = {
                    'active': True,
                    'state': 'running'
                }
        except:
            pass
        
        # UFW-Überprüfung
        try:
            ufw_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
            if ufw_result.returncode == 0 and 'active' in ufw_result.stdout.lower():
                result['detected_firewalls'].append('ufw')
                result['firewall_status']['ufw'] = {
                    'active': True,
                    'status': 'active'
                }
        except:
            pass
        
        return result
    
    def _detect_windows_firewall(self) -> Dict:
        """Erkennt Windows-Firewall."""
        result = {
            'detected_firewalls': [],
            'firewall_status': {},
            'rules_analysis': {}
        }
        
        try:
            # Windows-Firewall-Status
            netsh_result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                        capture_output=True, text=True, timeout=10)
            if netsh_result.returncode == 0:
                result['detected_firewalls'].append('windows_firewall')
                
                # Analysiere Firewall-Status
                if 'State ON' in netsh_result.stdout:
                    result['firewall_status']['windows_firewall'] = {
                        'active': True,
                        'state': 'ON'
                    }
                else:
                    result['firewall_status']['windows_firewall'] = {
                        'active': False,
                        'state': 'OFF'
                    }
        except:
            pass
        
        return result
    
    def _detect_macos_firewall(self) -> Dict:
        """Erkennt macOS-Firewall."""
        result = {
            'detected_firewalls': [],
            'firewall_status': {},
            'rules_analysis': {}
        }
        
        try:
            # pf (Packet Filter) - Standard-Firewall von macOS
            pfctl_result = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True, timeout=10)
            if pfctl_result.returncode == 0 and pfctl_result.stdout:
                result['detected_firewalls'].append('pf')
                result['firewall_status']['pf'] = {
                    'active': True,
                    'rules_count': len(pfctl_result.stdout.split('\n'))
                }
        except:
            pass
        
        return result
    
    def _analyze_iptables_rules(self, rules_output: str) -> Dict:
        """Analysiert iptables-Regeln."""
        analysis = {
            'drop_rules': 0,
            'reject_rules': 0,
            'accept_rules': 0,
            'blocking_behavior': 'unknown'
        }
        
        lines = rules_output.split('\n')
        for line in lines:
            line_lower = line.lower()
            if 'drop' in line_lower:
                analysis['drop_rules'] += 1
            elif 'reject' in line_lower:
                analysis['reject_rules'] += 1
            elif 'accept' in line_lower:
                analysis['accept_rules'] += 1
        
        # Bestimme Blockierverhalten
        if analysis['drop_rules'] > analysis['accept_rules']:
            analysis['blocking_behavior'] = 'restrictive'
        elif analysis['accept_rules'] > analysis['drop_rules']:
            analysis['blocking_behavior'] = 'permissive'
        else:
            analysis['blocking_behavior'] = 'balanced'
        
        return analysis
    
    def bypass_firewall_detection(self, target: str) -> Dict:
        """Versucht, Firewall-Erkennung zu umgehen."""
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'bypass_methods': {},
            'successful_bypass': [],
            'recommendations': []
        }
        
        # Verschiedene Umgehungsmethoden
        bypass_methods = {
            'fragmentation': self._test_fragmentation,
            'source_port_manipulation': self._test_source_port_manipulation,
            'ttl_manipulation': self._test_ttl_manipulation,
            'protocol_switching': self._test_protocol_switching,
            'timing_variation': self._test_timing_variation
        }
        
        for method_name, method_func in bypass_methods.items():
            try:
                bypass_result = method_func(target)
                result['bypass_methods'][method_name] = bypass_result
                
                if bypass_result.get('successful', False):
                    result['successful_bypass'].append(method_name)
                    
            except Exception as e:
                result['bypass_methods'][method_name] = {'error': str(e)}
        
        # Erstelle Empfehlungen
        if result['successful_bypass']:
            result['recommendations'].append(f"Die folgenden Methoden waren erfolgreich: {', '.join(result['successful_bypass'])}")
        else:
            result['recommendations'].append("Keine erfolgreichen Umgehungsmethoden gefunden. Firewall scheint robust zu sein.")
        
        return result
    
    def _test_fragmentation(self, target: str) -> Dict:
        """Testet IP-Fragmentierung zur Umgehung."""
        result = {
            'method': 'ip_fragmentation',
            'successful': False,
            'test_results': {}
        }
        
        # Dies ist eine simulierte Implementierung
        # In der Praxis würde man raw sockets verwenden
        result['test_results'] = {
            'fragmentation_supported': 'simulated',
            'firewall_bypass_possible': 'unknown',
            'note': 'Erfordert raw sockets und root-Rechte'
        }
        
        return result
    
    def _test_source_port_manipulation(self, target: str) -> Dict:
        """Testet Source-Port-Manipulation."""
        result = {
            'method': 'source_port_manipulation',
            'successful': False,
            'tested_ports': [],
            'successful_ports': []
        }
        
        # Teste verschiedene Source-Ports
        test_ports = [53, 80, 443, 123, 22, 21, 25, 110]
        
        for src_port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('', src_port))
                sock.settimeout(3)
                
                connect_result = sock.connect_ex((target, 80))
                
                if connect_result == 0:
                    result['successful_ports'].append(src_port)
                    result['successful'] = True
                
                result['tested_ports'].append(src_port)
                sock.close()
                
            except Exception as e:
                result['tested_ports'].append(src_port)
                result[f'port_{src_port}_error'] = str(e)
        
        return result
    
    def _test_ttl_manipulation(self, target: str) -> Dict:
        """Testet TTL-Manipulation."""
        result = {
            'method': 'ttl_manipulation',
            'successful': False,
            'note': 'Erfordert raw sockets für vollständige Implementierung'
        }
        
        # TTL-Manipulation erfordert normalerweise raw sockets
        # Dies ist eine Platzhalter-Implementierung
        return result
    
    def _test_protocol_switching(self, target: str) -> Dict:
        """Testet Protokoll-Wechsel."""
        result = {
            'method': 'protocol_switching',
            'successful': False,
            'tested_protocols': [],
            'successful_protocols': []
        }
        
        protocols = [
            ('TCP', socket.SOCK_STREAM),
            ('UDP', socket.SOCK_DGRAM)
        ]
        
        for proto_name, proto_type in protocols:
            try:
                sock = socket.socket(socket.AF_INET, proto_type)
                sock.settimeout(3)
                
                if proto_type == socket.SOCK_STREAM:
                    connect_result = sock.connect_ex((target, 80))
                    success = (connect_result == 0)
                else:
                    # Für UDP senden wir einfach ein Paket
                    sock.sendto(b'test', (target, 53))
                    success = True  # Erfolg bei UDP bedeutet nur, dass sendto funktioniert
                
                result['tested_protocols'].append(proto_name)
                
                if success:
                    result['successful_protocols'].append(proto_name)
                    result['successful'] = True
                
                sock.close()
                
            except Exception as e:
                result['tested_protocols'].append(proto_name)
                result[f'{proto_name}_error'] = str(e)
        
        return result
    
    def _test_timing_variation(self, target: str) -> Dict:
        """Testet Timing-Variationen."""
        result = {
            'method': 'timing_variation',
            'successful': False,
            'test_delays': [0.1, 0.5, 1.0, 2.0],
            'successful_delays': []
        }
        
        for delay in result['test_delays']:
            try:
                time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                connect_result = sock.connect_ex((target, 80))
                
                if connect_result == 0:
                    result['successful_delays'].append(delay)
                    result['successful'] = True
                
                sock.close()
                
            except Exception as e:
                result[f'delay_{delay}_error'] = str(e)
        
        return result
    
    def save_results(self, filename: str = None):
        """Speichert alle Ergebnisse."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"firewall_detection_{timestamp}.json"
        
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'results': self.results,
            'evidence': self.evidence,
            'summary': {
                'total_scans': len(self.results),
                'firewall_detections': len([r for r in self.results.values() if 'detected_firewalls' in r and r['detected_firewalls']])
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse gespeichert: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Firewall-Detection-Tool')
    parser.add_argument('target', help='Ziel-IP oder -Hostname')
    parser.add_argument('-p', '--port', type=int, default=80, help='Port für Tests')
    parser.add_argument('--full-scan', action='store_true', help='Vollständigen Port-Scan durchführen')
    parser.add_argument('--detect-system', action='store_true', help='System-Firewall erkennen')
    parser.add_argument('--bypass-test', action='store_true', help='Bypass-Methoden testen')
    parser.add_argument('-o', '--output', help='Ausgabedatei')
    
    args = parser.parse_args()
    
    detector = FirewallDetector()
    
    print(f"Starte Firewall-Erkennung für: {args.target}")
    
    # Standard-Firewall-Erkennung
    result = detector.detect_firewall_by_response(args.target, args.port)
    
    print(f"Erkannte Firewalls: {result.get('detected_firewalls', [])}")
    
    # Optionale Tests
    if args.full_scan:
        print("Führe vollständigen Port-Scan durch...")
        scan_result = detector.scan_ports(args.target)
        print(f"Blockierte Ports: {len(scan_result['blocked_ports'])}")
        print(f"Gefilterte Ports: {len(scan_result['filtered_ports'])}")
        
    if args.detect_system:
        print("Erkenne System-Firewall...")
        system_result = detector.detect_system_firewall()
        print(f"Erkannte System-Firewalls: {system_result.get('detected_firewalls', [])}")
        
    if args.bypass_test:
        print("Teste Bypass-Methoden...")
        bypass_result = detector.bypass_firewall_detection(args.target)
        print(f"Erfolgreiche Bypass-Methoden: {bypass_result.get('successful_bypass', [])}")
    
    # Ergebnisse speichern
    if args.output:
        detector.results[args.target] = result
        detector.save_results(args.output)
    else:
        detector.results[args.target] = result
        detector.save_results()

if __name__ == '__main__':
    main()