#!/usr/bin/env python3
"""
Common-Paths-Scanner
Scannt häufige Pfade, Endpunkte und versteckte Ressourcen.
Kann blockierte Anfragen freigeben und Firewalls identifizieren.
"""

import requests
import concurrent.futures
import argparse
import json
import time
import random
import string
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import urllib3
from urllib.parse import urljoin, urlparse
import re

# Deaktiviere SSL-Warnungen
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CommonPathsScanner:
    def __init__(self):
        self.common_paths = [
            # Web-Root
            '/', '/index.html', '/index.php', '/index.asp', '/index.aspx',
            '/default.html', '/default.php', '/default.asp', '/default.aspx',
            '/home.html', '/home.php', '/home.asp', '/home.aspx',
            
            # Admin-Bereiche
            '/admin', '/admin/', '/administrator', '/administrator/',
            '/admin.php', '/admin.asp', '/admin.aspx', '/admin.jsp',
            '/login', '/login/', '/login.php', '/login.asp', '/login.aspx',
            '/signin', '/signin/', '/signin.php', '/signin.asp',
            '/auth', '/auth/', '/authenticate', '/authentication',
            '/wp-admin', '/wp-admin/', '/wordpress/wp-admin',
            '/drupal/admin', '/joomla/administrator',
            
            # Konfigurationsdateien
            '/config.php', '/configuration.php', '/settings.php',
            '/config.xml', '/config.json', '/config.ini',
            '/web.config', '/app.config', '/settings.xml',
            '/.env', '/.htaccess', '/.htpasswd', '/robots.txt',
            '/php.ini', '/phpinfo.php', '/info.php',
            
            # API-Endpunkte
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/', '/rest/api', '/rest/v1',
            '/graphql', '/graphql/', '/api/graphql',
            '/swagger', '/swagger/', '/swagger-ui', '/swagger-ui.html',
            '/api-docs', '/api-docs/', '/api/documentation',
            '/openapi.json', '/swagger.json', '/swagger.yaml',
            
            # Backup-Dateien
            '/backup', '/backup/', '/backups', '/backups/',
            '/backup.zip', '/backup.tar', '/backup.tar.gz',
            '/backup.sql', '/backup.db', '/backup.xml',
            '/old', '/old/', '/backup_old', '/old_backup',
            '/archive', '/archive/', '/archives', '/archives/',
            
            # Dokumentation
            '/docs', '/docs/', '/documentation', '/documentation/',
            '/manual', '/manual/', '/guide', '/guide/',
            '/readme', '/readme.txt', '/README.md', '/INSTALL.txt',
            '/CHANGELOG', '/CHANGELOG.txt', '/CHANGES.txt',
            '/LICENSE', '/LICENSE.txt', '/COPYING',
            
            # Versteckte Verzeichnisse
            '/hidden', '/hidden/', '/private', '/private/',
            '/secret', '/secret/', '/confidential', '/confidential/',
            '/internal', '/internal/', '/restricted', '/restricted/',
            '/test', '/test/', '/testing', '/testing/',
            '/dev', '/dev/', '/development', '/development/',
            '/staging', '/staging/', '/prod', '/production/',
            
            # Upload-Bereiche
            '/upload', '/upload/', '/uploads', '/uploads/',
            '/fileupload', '/fileupload/', '/upload.php',
            '/files', '/files/', '/documents', '/documents/',
            '/media', '/media/', '/images', '/images/',
            '/assets', '/assets/', '/static', '/static/',
            
            # Datenbank- und Debug-Endpunkte
            '/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/',
            '/mysql', '/mysql-admin', '/adminer', '/adminer.php',
            '/dbadmin', '/db-admin', '/database-admin',
            '/debug', '/debug/', '/debugger', '/debugging/',
            '/trace', '/trace/', '/tracing', '/traces/',
            '/error', '/error/', '/errors', '/errors/',
            '/log', '/log/', '/logs', '/logs/', '/logging',
            
            # CMS-spezifische Pfade
            '/wp-content', '/wp-content/', '/wp-includes', '/wp-includes/',
            '/wp-json', '/wp-json/', '/xmlrpc.php', '/wp-trackback.php',
            '/joomla', '/joomla/', '/components', '/components/',
            '/drupal', '/drupal/', '/sites', '/sites/default',
            '/typo3', '/typo3/', '/typo3conf', '/typo3temp',
            
            # Mobile und moderne Endpunkte
            '/mobile', '/mobile/', '/m', '/m/',
            '/api/mobile', '/api/mobile/v1',
            '/app', '/app/', '/apps', '/apps/',
            '/service', '/service/', '/services', '/services/',
            '/endpoint', '/endpoint/', '/endpoints', '/endpoints/',
            
            # Sicherheitsrelevante Pfade
            '/security', '/security/', '/secure', '/secure/',
            '/ssl', '/ssl/', '/tls', '/tls/',
            '/cert', '/cert/', '/certs', '/certs/',
            '/certificate', '/certificate/', '/certificates', '/certificates/',
            '/key', '/key/', '/keys', '/keys/',
            '/token', '/token/', '/tokens', '/tokens/',
            
            # Cloud und CDN-Pfade
            '/s3', '/s3/', '/bucket', '/bucket/',
            '/cdn', '/cdn/', '/cloudfront', '/cloudfront/',
            '/azure', '/azure/', '/aws', '/aws/',
            '/gcp', '/gcp/', '/cloud', '/cloud/',
            
            # Versionierungs-Endpunkte
            '/version', '/version/', '/versions', '/versions/',
            '/v1', '/v1/', '/v2', '/v2/', '/v3', '/v3/',
            '/api/v1', '/api/v2', '/api/v3', '/api/v4',
            '/beta', '/beta/', '/alpha', '/alpha/',
            '/release', '/release/', '/releases', '/releases/'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'
        ]
        
        self.file_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.js', '.css',
            '.json', '.xml', '.txt', '.md', '.py', '.rb', '.pl', '.sh',
            '.sql', '.db', '.sqlite', '.mdb', '.accdb', '.bak', '.backup',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.swf',
            '.log', '.old', '.tmp', '.temp', '.cache', '.session'
        ]
        
        self.results = {}
        self.firewall_indicators = []
        self.blocked_paths = []
        
    def scan_common_paths(self, base_url: str, paths: List[str] = None) -> Dict:
        """Scannt häufige Pfade und Endpunkte."""
        if paths is None:
            paths = self.common_paths
        
        result = {
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'scanned_paths': [],
            'found_paths': [],
            'blocked_paths': [],
            'firewall_indicators': [],
            'scan_statistics': {
                'total_scanned': 0,
                'found': 0,
                'blocked': 0,
                'errors': 0
            }
        }
        
        print(f"Starte Common-Paths-Scan für: {base_url}")
        print(f"Anzahl der zu scannenden Pfade: {len(paths)}")
        
        def scan_path(path):
            """Scannt einen einzelnen Pfad."""
            full_url = urljoin(base_url, path)
            
            try:
                # Wähle zufälligen User-Agent
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache'
                }
                
                # Führe Anfrage durch
                response = requests.get(
                    full_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
                
                scan_result = {
                    'path': path,
                    'url': full_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'headers': dict(response.headers),
                    'redirects': len(response.history),
                    'found': False,
                    'blocked': False,
                    'error': None
                }
                
                # Analysiere Antwort
                if response.status_code == 200:
                    scan_result['found'] = True
                    # Analysiere Inhalt auf interessante Informationen
                    scan_result['content_analysis'] = self._analyze_content(response.text, path)
                    
                elif response.status_code in [403, 406, 423]:
                    scan_result['blocked'] = True
                    scan_result['block_reason'] = f'HTTP {response.status_code}'
                    
                elif response.status_code in [401, 407]:
                    scan_result['found'] = True
                    scan_result['authentication_required'] = True
                    
                # Firewall-Erkennung
                firewall_detected = self._detect_firewall_from_response(response, path)
                if firewall_detected:
                    scan_result['firewall_detected'] = firewall_detected
                
                return scan_result
                
            except requests.exceptions.Timeout:
                return {
                    'path': path,
                    'url': full_url,
                    'error': 'Timeout',
                    'blocked': True,
                    'block_reason': 'timeout'
                }
            except requests.exceptions.ConnectionError as e:
                return {
                    'path': path,
                    'url': full_url,
                    'error': f'Connection Error: {str(e)}',
                    'blocked': True,
                    'block_reason': 'connection_error'
                }
            except requests.exceptions.RequestException as e:
                return {
                    'path': path,
                    'url': full_url,
                    'error': f'Request Error: {str(e)}',
                    'blocked': False,
                    'block_reason': 'request_error'
                }
            except Exception as e:
                return {
                    'path': path,
                    'url': full_url,
                    'error': f'Unexpected Error: {str(e)}',
                    'blocked': False,
                    'block_reason': 'unexpected_error'
                }
        
        # Führe parallelen Scan durch
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_path, path) for path in paths]
            
            for future in concurrent.futures.as_completed(futures):
                scan_result = future.result()
                result['scanned_paths'].append(scan_result)
                
                # Aktualisiere Statistiken
                if scan_result.get('found'):
                    result['found_paths'].append(scan_result)
                elif scan_result.get('blocked'):
                    result['blocked_paths'].append(scan_result)
                elif scan_result.get('error'):
                    result['scan_statistics']['errors'] += 1
        
        # Aktualisiere finale Statistiken
        result['scan_statistics']['total_scanned'] = len(result['scanned_paths'])
        result['scan_statistics']['found'] = len(result['found_paths'])
        result['scan_statistics']['blocked'] = len(result['blocked_paths'])
        
        # Analysiere auf Firewall-Muster
        result['firewall_indicators'] = self._analyze_firewall_patterns(result)
        
        return result
    
    def _analyze_content(self, content: str, path: str) -> Dict:
        """Analysiert Inhalt auf interessante Informationen."""
        analysis = {
            'interesting_patterns': [],
            'sensitive_data': [],
            'technology_stack': [],
            'potential_vulnerabilities': []
        }
        
        content_lower = content.lower()
        
        # Suche nach interessanten Mustern
        interesting_patterns = [
            ('database error', 'database_error'),
            ('sql syntax', 'sql_error'),
            ('mysql', 'mysql_detected'),
            ('postgresql', 'postgresql_detected'),
            ('oracle', 'oracle_detected'),
            ('microsoft sql', 'mssql_detected'),
            ('php fatal error', 'php_error'),
            ('java.lang', 'java_error'),
            ('traceback', 'python_error'),
            ('stack trace', 'stack_trace'),
            ('debug mode', 'debug_mode'),
            ('version', 'version_info'),
            ('build', 'build_info'),
            ('internal server error', 'server_error'),
            ('access denied', 'access_denied'),
            ('permission denied', 'permission_denied'),
            ('not found', 'not_found'),
            ('forbidden', 'forbidden'),
            ('unauthorized', 'unauthorized')
        ]
        
        for pattern, category in interesting_patterns:
            if pattern in content_lower:
                analysis['interesting_patterns'].append(category)
        
        # Suche nach sensiblen Daten
        sensitive_patterns = [
            (r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'password'),
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'api_key'),
            (r'secret["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'secret'),
            (r'token["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'token'),
            (r'database["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'database_name'),
            (r'username["\']?\s*[:=]\s*["\']?([^"\'\s]+)', 'username')
        ]
        
        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['sensitive_data'].append(f'{data_type}:found')
        
        # Erkenne Technologie-Stack
        tech_patterns = [
            ('apache', 'apache_server'),
            ('nginx', 'nginx_server'),
            ('iis', 'iis_server'),
            ('lighttpd', 'lighttpd_server'),
            ('tomcat', 'tomcat_server'),
            ('jboss', 'jboss_server'),
            ('node.js', 'nodejs'),
            ('express', 'express_framework'),
            ('django', 'django_framework'),
            ('flask', 'flask_framework'),
            ('rails', 'rails_framework'),
            ('spring', 'spring_framework'),
            ('php', 'php_language'),
            ('python', 'python_language'),
            ('ruby', 'ruby_language'),
            ('java', 'java_language'),
            ('javascript', 'javascript_language')
        ]
        
        for tech, tech_type in tech_patterns:
            if tech in content_lower:
                analysis['technology_stack'].append(tech_type)
        
        return analysis
    
    def _detect_firewall_from_response(self, response, path: str) -> Optional[str]:
        """Erkennt Firewalls anhand von HTTP-Antworten."""
        # Prüfe HTTP-Status-Codes
        if response.status_code in [403, 406, 423, 429]:
            return 'access_denied'
        
        # Prüfe Header
        headers = dict(response.headers)
        header_str = str(headers).lower()
        
        firewall_indicators = [
            'cloudflare', 'cf-ray', 'cloudfront', 'akamai',
            'sucuri', 'wordfence', 'iThemes Security',
            'mod_security', 'modsecurity', 'awselb',
            'x-sucuri', 'x-wordfence', 'x-wffw',
            'server: nginx', 'server: apache', 'server: iis'
        ]
        
        for indicator in firewall_indicators:
            if indicator in header_str:
                return f'firewall_detected_{indicator.replace(" ", "_")}'
        
        # Prüfe auf Rate-Limiting
        if response.status_code == 429:
            return 'rate_limiting_detected'
        
        # Prüfe auf WAF-Signaturen im Inhalt
        content_indicators = [
            'cloudflare', 'sucuri', 'wordfence', 'blocked by',
            'access denied', 'forbidden', 'not allowed'
        ]
        
        content_lower = response.text.lower()
        for indicator in content_indicators:
            if indicator in content_lower:
                return f'content_firewall_{indicator.replace(" ", "_")}'
        
        return None
    
    def _analyze_firewall_patterns(self, scan_result: Dict) -> List[str]:
        """Analysiert Scan-Ergebnisse auf Firewall-Muster."""
        indicators = []
        
        blocked_count = scan_result['scan_statistics']['blocked']
        total_count = scan_result['scan_statistics']['total_scanned']
        
        # Wenn viele Anfragen blockiert wurden, deutet das auf eine Firewall hin
        if blocked_count > total_count * 0.2:  # >20% blockiert
            indicators.append('high_blocking_rate')
        
        # Wenn alle Anfragen timeouts haben
        timeout_errors = sum(1 for path in scan_result['scanned_paths'] 
                           if path.get('error') == 'Timeout')
        if timeout_errors > total_count * 0.1:
            indicators.append('many_timeouts')
        
        # Prüfe auf bestimmte Blockier-Muster
        for blocked_path in scan_result['blocked_paths']:
            block_reason = blocked_path.get('block_reason', '')
            if 'timeout' in block_reason.lower():
                indicators.append('timeout_based_blocking')
            elif 'connection_error' in block_reason.lower():
                indicators.append('connection_based_blocking')
        
        return indicators
    
    def scan_file_extensions(self, base_url: str, extensions: List[str] = None) -> Dict:
        """Scannt nach Dateien mit bestimmten Erweiterungen."""
        if extensions is None:
            extensions = self.file_extensions
        
        result = {
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'scanned_extensions': [],
            'found_files': [],
            'method': 'extension_scan'
        }
        
        # Basis-Dateinamen für Test
        base_names = ['index', 'config', 'settings', 'backup', 'test', 'admin', 'login', 'data']
        
        for ext in extensions:
            for base_name in base_names:
                filename = f"{base_name}{ext}"
                url = urljoin(base_url, filename)
                
                try:
                    headers = {
                        'User-Agent': random.choice(self.user_agents),
                        'Accept': '*/*'
                    }
                    
                    response = requests.head(url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        file_info = {
                            'filename': filename,
                            'url': url,
                            'extension': ext,
                            'content_length': response.headers.get('Content-Length'),
                            'content_type': response.headers.get('Content-Type'),
                            'last_modified': response.headers.get('Last-Modified')
                        }
                        result['found_files'].append(file_info)
                    
                    result['scanned_extensions'].append({
                        'extension': ext,
                        'filename': filename,
                        'status_code': response.status_code
                    })
                    
                except Exception as e:
                    result['scanned_extensions'].append({
                        'extension': ext,
                        'filename': filename,
                        'error': str(e)
                    })
        
        return result
    
    def generate_wordlist_scan(self, base_url: str, wordlist: List[str] = None) -> Dict:
        """Scannt mit einer benutzerdefinierten Wortliste."""
        if wordlist is None:
            # Erstelle eine kleine Standard-Wortliste
            wordlist = [
                'admin', 'backup', 'config', 'data', 'db', 'debug', 'dev',
                'download', 'files', 'hidden', 'images', 'include', 'inc',
                'install', 'js', 'lib', 'library', 'log', 'logs', 'mail',
                'media', 'old', 'private', 'public', 'secret', 'setup',
                'src', 'temp', 'test', 'tmp', 'upload', 'uploads',
                'user', 'users', 'var', 'web', 'www'
            ]
        
        result = {
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'wordlist_size': len(wordlist),
            'found_items': [],
            'method': 'wordlist_scan'
        }
        
        for word in wordlist:
            # Teste verschiedene Varianten
            variations = [
                word,
                f"{word}/",
                f"{word}.php",
                f"{word}.html",
                f"{word}.asp",
                f"{word}.aspx",
                f"{word}.jsp",
                f"{word}.txt",
                f"{word}.xml",
                f"{word}.json",
                f"{word}1",
                f"{word}2",
                f"{word}3",
                f"old_{word}",
                f"{word}_old",
                f"backup_{word}",
                f"{word}_backup"
            ]
            
            for variation in variations:
                url = urljoin(base_url, variation)
                
                try:
                    headers = {
                        'User-Agent': random.choice(self.user_agents),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                    
                    response = requests.get(url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        item_info = {
                            'word': word,
                            'variation': variation,
                            'url': url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        }
                        result['found_items'].append(item_info)
                        break  # Nicht weitere Variationen testen, wenn eine funktioniert
                        
                except:
                    continue
        
        return result
    
    def intelligent_scan(self, base_url: str) -> Dict:
        """Führt einen intelligenten Scan mit verschiedenen Techniken durch."""
        result = {
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'scan_phases': {},
            'combined_results': {},
            'intelligence_analysis': {}
        }
        
        print(f"Starte intelligenten Scan für: {base_url}")
        
        # Phase 1: Common Paths
        print("Phase 1: Scanning common paths...")
        phase1_result = self.scan_common_paths(base_url)
        result['scan_phases']['common_paths'] = phase1_result
        
        # Phase 2: File Extensions
        print("Phase 2: Scanning file extensions...")
        phase2_result = self.scan_file_extensions(base_url)
        result['scan_phases']['file_extensions'] = phase2_result
        
        # Phase 3: Wordlist Scan
        print("Phase 3: Wordlist scanning...")
        phase3_result = self.generate_wordlist_scan(base_url)
        result['scan_phases']['wordlist_scan'] = phase3_result
        
        # Kombiniere und analysiere Ergebnisse
        result['combined_results'] = self._combine_scan_results(result['scan_phases'])
        result['intelligence_analysis'] = self._analyze_intelligence_results(result)
        
        return result
    
    def _combine_scan_results(self, scan_phases: Dict) -> Dict:
        """Kombiniert Ergebnisse aus verschiedenen Scan-Phasen."""
        combined = {
            'total_found': 0,
            'unique_paths': [],
            'path_categories': {},
            'technology_indicators': []
        }
        
        all_found = []
        
        # Sammle alle gefundenen Pfade
        for phase_name, phase_result in scan_phases.items():
            if 'found_paths' in phase_result:
                all_found.extend(phase_result['found_paths'])
            elif 'found_files' in phase_result:
                all_found.extend(phase_result['found_files'])
            elif 'found_items' in phase_result:
                all_found.extend(phase_result['found_items'])
        
        # Entferne Duplikate
        unique_paths = []
        seen_paths = set()
        
        for item in all_found:
            path = item.get('path') or item.get('filename') or item.get('variation') or item.get('word')
            if path and path not in seen_paths:
                seen_paths.add(path)
                unique_paths.append(item)
        
        combined['unique_paths'] = unique_paths
        combined['total_found'] = len(unique_paths)
        
        # Kategorisiere Pfade
        for item in unique_paths:
            path = item.get('path') or item.get('filename') or item.get('variation') or item.get('word')
            if path:
                category = self._categorize_path(path)
                if category not in combined['path_categories']:
                    combined['path_categories'][category] = []
                combined['path_categories'][category].append(path)
        
        return combined
    
    def _categorize_path(self, path: str) -> str:
        """Kategorisiert einen Pfad."""
        path_lower = path.lower()
        
        if any(admin_word in path_lower for admin_word in ['admin', 'login', 'auth', 'user']):
            return 'authentication'
        elif any(api_word in path_lower for api_word in ['api', 'rest', 'graphql', 'service']):
            return 'api'
        elif any(backup_word in path_lower for backup_word in ['backup', 'old', 'archive']):
            return 'backup'
        elif any(config_word in path_lower for config_word in ['config', 'settings', 'env']):
            return 'configuration'
        elif any(dev_word in path_lower for dev_word in ['dev', 'test', 'debug']):
            return 'development'
        elif any(upload_word in path_lower for upload_word in ['upload', 'file', 'media']):
            return 'upload'
        else:
            return 'general'
    
    def _analyze_intelligence_results(self, result: Dict) -> Dict:
        """Analysiert die kombinierten Ergebnisse intelligent."""
        analysis = {
            'attack_surface_assessment': 'unknown',
            'security_maturity': 'unknown',
            'recommended_focus_areas': [],
            'high_value_targets': [],
            'potential_entry_points': []
        }
        
        combined_results = result['combined_results']
        total_found = combined_results['total_found']
        
        # Bewerte Angriffsoberfläche
        if total_found > 50:
            analysis['attack_surface_assessment'] = 'large'
        elif total_found > 20:
            analysis['attack_surface_assessment'] = 'medium'
        else:
            analysis['attack_surface_assessment'] = 'small'
        
        # Bewerte Sicherheitsreife
        categories = combined_results['path_categories']
        if 'api' in categories or 'authentication' in categories:
            analysis['security_maturity'] = 'potentially_mature'
        elif 'development' in categories or 'backup' in categories:
            analysis['security_maturity'] = 'potentially_weak'
        else:
            analysis['security_maturity'] = 'unknown'
        
        # Empfohlene Fokusbereiche
        if 'api' in categories:
            analysis['recommended_focus_areas'].append('api_security')
        if 'authentication' in categories:
            analysis['recommended_focus_areas'].append('authentication_mechanisms')
        if 'backup' in categories:
            analysis['recommended_focus_areas'].append('backup_security')
        if 'development' in categories:
            analysis['recommended_focus_areas'].append('development_exposure')
        
        # Identifiziere wertvolle Ziele
        for category, paths in categories.items():
            if category in ['api', 'authentication', 'backup', 'configuration']:
                analysis['high_value_targets'].extend(paths[:5])  # Max 5 pro Kategorie
        
        return analysis
    
    def save_results(self, filename: str = None):
        """Speichert alle Ergebnisse."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"common_paths_scan_{timestamp}.json"
        
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'results': self.results,
            'firewall_indicators': self.firewall_indicators,
            'blocked_paths': self.blocked_paths,
            'summary': {
                'total_scans': len(self.results),
                'total_found_paths': sum(len(r.get('found_paths', [])) for r in self.results.values()),
                'total_blocked_paths': sum(len(r.get('blocked_paths', [])) for r in self.results.values())
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse gespeichert: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Common-Paths-Scanner')
    parser.add_argument('url', help='Ziel-URL')
    parser.add_argument('-m', '--mode', choices=['common', 'extensions', 'wordlist', 'intelligent'],
                       default='common', help='Scan-Modus')
    parser.add_argument('-o', '--output', help='Ausgabedatei')
    parser.add_argument('--timeout', type=int, default=10, help='Request-Timeout')
    parser.add_argument('--threads', type=int, default=20, help='Anzahl Threads')
    
    args = parser.parse_args()
    
    scanner = CommonPathsScanner()
    
    print(f"Starte Common-Paths-Scan für: {args.url}")
    print(f"Scan-Modus: {args.mode}")
    
    # Führe entsprechenden Scan durch
    if args.mode == 'common':
        result = scanner.scan_common_paths(args.url)
    elif args.mode == 'extensions':
        result = scanner.scan_file_extensions(args.url)
    elif args.mode == 'wordlist':
        result = scanner.generate_wordlist_scan(args.url)
    elif args.mode == 'intelligent':
        result = scanner.intelligent_scan(args.url)
    
    # Zeige Zusammenfassung
    if 'scan_statistics' in result:
        stats = result['scan_statistics']
        print(f"\nScan abgeschlossen!")
        print(f"Gefundene Pfade: {stats.get('found', 0)}")
        print(f"Blockierte Pfade: {stats.get('blocked', 0)}")
        print(f"Fehler: {stats.get('errors', 0)}")
    
    # Ergebnisse speichern
    if args.output:
        scanner.results[args.url] = result
        scanner.save_results(args.output)
    else:
        scanner.results[args.url] = result
        scanner.save_results()

if __name__ == '__main__':
    main()