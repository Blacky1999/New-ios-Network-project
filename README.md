# Netzwerk-Heuristiken Suite

Eine umfassende Sammlung von Tools für DNS-Probing, Leak-Tests, Firewall-Erkennung und das Scannen häufiger Pfade. Diese Suite kann blockierte DNS-Anfragen freigeben und Firewalls identifizieren.

## 🚀 Features

### DNS-Probing Tool (`dns_probing.py`)
- **Multi-Server DNS-Analyse**: Testet DNS-Anfragen gegen verschiedene DNS-Server (Google, Cloudflare, Quad9, OpenDNS)
- **Firewall-Erkennung**: Erkennt DNS-basierte Firewalls anhand von Antwortzeiten und Blockaden
- **DNS-Hijacking-Detection**: Identifiziert mögliches DNS-Hijacking
- **DNS-Traceroute**: Führt DNS-Traceroute für Pfadanalyse durch
- **Common Record Scan**: Scannt häufige DNS-Record-Typen (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR)

### DNS-Leak-Test Tool (`dns_leak_test.py`)
- **DNS-Leak-Erkennung**: Identifiziert DNS-Leaks und überprüft, ob DNS-Anfragen über unerwünschte Server laufen
- **Multi-Technik-Testing**: Standard-DNS, Extended-DNS, DNS-over-HTTPS, DNS-over-TLS
- **System-DNS-Ermittlung**: Ermittelt aktuelle DNS-Server des Systems
- **Risikobewertung**: Bewertet das DNS-Leak-Risiko (low/medium/high)
- **Detaillierte Berichte**: Generiert umfassende Berichte über gefundene Leaks

### Firewall-Detection Tool (`firewall_detector.py`)
- **Firewall-Typ-Erkennung**: Erkennt verschiedene Firewall-Typen (iptables, Windows Firewall, pfSense, Cisco ASA, etc.)
- **Port-Scan mit Firewall-Erkennung**: Scannt Ports und identifiziert firewall-basierte Blockaden
- **System-Firewall-Erkennung**: Erkennt die auf dem lokalen System laufende Firewall
- **Bypass-Methoden-Testing**: Testet verschiedene Methoden zur Umgehung von Firewalls
- **Response-Analyse**: Analysiert Antwortzeiten und -muster zur Firewall-Erkennung

### Common-Paths-Scanner (`common_paths_scanner.py`)
- **Umfassende Pfad-Datenbank**: Über 200 vordefinierte häufige Pfade und Endpunkte
- **Multi-Scan-Modi**: Common paths, file extensions, wordlist scan, intelligenter Scan
- **Firewall-Erkennung**: Erkennt Web Application Firewalls (WAF) und andere Schutzmaßnahmen
- **Content-Analyse**: Analysiert gefundene Inhalte auf interessante Informationen
- **Kategorisierung**: Kategorisiert gefundene Pfade (API, Authentication, Backup, etc.)

### Master-Suite (`network_heuristics.py`)
- **Einheitliche Schnittstelle**: Kombiniert alle Tools in einer einfachen CLI
- **Automatische Zieltyperkennung**: Erkennt automatisch, ob Domain, IP oder URL übergeben wurde
- **Umfassende Berichterstattung**: Generiert detaillierte Berichte in Text oder JSON
- **Risikobewertung**: Bewertet das Gesamtrisiko basierend auf allen Testergebnissen

## 📦 Installation

### Voraussetzungen
```bash
# Python 3.6+ erforderlich
python3 --version

# Installiere benötigte Pakete
pip install dnspython requests
```

### Repository klonen
```bash
git clone <repository-url>
cd network-heuristics
```

## 🎯 Verwendung

### Schnellstart - Vollständige Analyse
```bash
# Vollständige Analyse eines Domain-Namens
python3 network_heuristics.py example.com

# IP-Adresse analysieren
python3 network_heuristics.py 192.168.1.1

# URL analysieren
python3 network_heuristics.py https://example.com

# Mit Bericht generieren
python3 network_heuristics.py example.com --report
```

### Einzelne Tools verwenden

#### DNS-Probing
```bash
# Standard-DNS-Analyse
python3 dns_probing.py example.com

# Vollständiger DNS-Scan mit allen Features
python3 dns_probing.py example.com --full-scan

# Spezifische Record-Typen
python3 dns_probing.py example.com -r A AAAA MX TXT
```

#### DNS-Leak-Test
```bash
# Standard DNS-Leak-Test
python3 dns_leak_test.py

# Mit benutzerdefiniertem Testnamen
python3 dns_leak_test.py -t mein_test

# Mit detailliertem Bericht
python3 dns_leak_test.py --report
```

#### Firewall-Detection
```bash
# Standard Firewall-Erkennung
python3 firewall_detector.py 192.168.1.1

# Vollständige Firewall-Analyse
python3 firewall_detector.py 192.168.1.1 --full-scan

# System-Firewall erkennen
python3 firewall_detector.py --detect-system
```

#### Common-Paths-Scanner
```bash
# Intelligenter Scan
python3 common_paths_scanner.py https://example.com --mode intelligent

# Nur häufige Pfade scannen
python3 common_paths_scanner.py https://example.com --mode common

# File-Extension-Scan
python3 common_paths_scanner.py https://example.com --mode extensions
```

## 📊 Beispielausgaben

### DNS-Analyse
```
🔍 Führe DNS-Analyse durch für: example.com
DNS-Server getestet: 64
Blockierte Anfragen: 3
Firewall erkannt: 2
Durchschnittliche Antwortzeit: 0.234s
```

### DNS-Leak-Test
```
🔍 Führe DNS-Leak-Test durch: Standard-Test
Aktuelle DNS-Server: ['8.8.8.8', '1.1.1.1']
Gefundene Leaks: 0
Risikostufe: LOW
```

### Firewall-Erkennung
```
🔥 Führe Firewall-Erkennung durch für: 192.168.1.1
Erkannte Firewalls: ['iptables', 'ufw']
Port-Scan: 15 offene, 8 gefilterte Ports
System-Firewall: iptables (aktiv)
```

### Common-Paths-Scan
```
🗂️ Führe Common-Paths-Scan durch für: https://example.com
Gefundene Pfade: 47
API-Endpunkte: 8
Authentication: 5
Backup-Dateien: 3
Konfigurationsdateien: 12
```

## 🔧 Erweiterte Funktionen

### Firewall-Bypass-Methoden
Die Firewall-Detection umfasst verschiedene Bypass-Methoden:
- **IP-Fragmentierung**: Umgeht einfache Paketfilter
- **Source-Port-Manipulation**: Nutzt erlaubte Ports (53, 80, 443)
- **TTL-Manipulation**: Umgeht Hop-basierte Filter
- **Protokoll-Wechsel**: TCP/UDP-Wechsel
- **Timing-Variation**: Umgeht zeitbasierte Filter

### DNS-Leak-Umgehung
Das DNS-Leak-Test-Tool kann:
- DNS-over-HTTPS (DoH) testen
- DNS-over-TLS (DoT) simulieren
- System-DNS-Server ermitteln
- Verdächtige Antworten erkennen

### Intelligente Path-Analyse
Der Common-Paths-Scanner bietet:
- **Content-Analyse**: Sucht nach sensiblen Daten
- **Technologie-Erkennung**: Identifiziert verwendete Technologien
- **Kategorisierung**: Gruppiert Pfade nach Typ
- **WAF-Erkennung**: Erkennt Web Application Firewalls

## 🛡️ Sicherheitshinweise

### Verantwortungsvolle Verwendung
- **Nur auf eigenen Systemen oder mit Erlaubnis verwenden**
- **Keine illegalen Aktivitäten durchführen**
- **Respektiere Rate-Limiting und Server-Ressourcen**
- **Beachte lokale Gesetze und Vorschriften**

### Firewall-Respekt
- Die Tools sind für Testzwecke konzipiert
- Keine DoS-Attacken oder ähnliches
- Timeout-Werte sind konservativ gewählt
- Parallele Anfragen sind begrenzt

### Datenschutz
- Keine gespeicherten Nutzerdaten
- Lokale Ergebnisspeicherung
- Kein automatischer Datenversand
- SSL/TLS-Verification kann deaktiviert werden (nur für Tests)

## 📈 Fehlerbehandlung

### Häufige Probleme und Lösungen

#### DNS-Timeout
```bash
# Erhöhe DNS-Timeout
# In dns_probing.py: resolver.timeout = 10
```

#### Firewall-False-Positives
```bash
# Verwende zusätzliche Tests
python3 firewall_detector.py target --full-scan
```

#### Rate-Limiting
```bash
# Reduziere Thread-Anzahl
# In common_paths_scanner.py: max_workers=10
```

#### SSL-Zertifikat-Fehler
```bash
# SSL-Verification deaktivieren (nur für Tests)
# In Requests: verify=False
```

## 🔍 Troubleshooting

### Debug-Modus
```python
# Aktiviere Debug-Logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Einzelne Tests isolieren
```bash
# Teste nur spezifische Komponenten
python3 dns_probing.py example.com --test-specific-function
```

### Netzwerk-Konnektivität prüfen
```bash
# Basis-Konnektivität testen
ping example.com
nslookup example.com
curl -I https://example.com
```

## 📚 Weiterführende Informationen

### DNS-Sicherheit
- [DNS Security Extensions (DNSSEC)](https://www.icann.org/dnssec)
- [DNS-over-HTTPS (DoH)](https://en.wikipedia.org/wiki/DNS_over_HTTPS)
- [DNS-over-TLS (DoT)](https://en.wikipedia.org/wiki/DNS_over_TLS)

### Firewall-Technologien
- [iptables Documentation](https://www.netfilter.org/documentation/)
- [Windows Firewall](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security)
- [Web Application Firewalls (WAF)](https://owasp.org/www-community/Web_Application_Firewall)

### Web-Sicherheit
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)

## 🤝 Beitrag

Beiträge sind willkommen! Bitte beachten:
- Code-Kommentare auf Deutsch oder Englisch
- Tests für neue Funktionen
- Dokumentation aktualisieren
- Sicherheitsaspekte berücksichtigen

## 📄 Lizenz

Dieses Projekt ist für Bildungs- und Testzwecke konzipiert. Die Verantwortung für die Verwendung liegt beim Benutzer.

---

**⚠️ Haftungsausschluss**: Diese Tools sind für legitime Sicherheitstests und Forschung gedacht. Der Missbrauch für illegale Aktiviten ist strengstens untersagt.