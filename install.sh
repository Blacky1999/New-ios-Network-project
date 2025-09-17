#!/bin/bash
# Installationsscript für Netzwerk-Heuristiken Suite

echo "🚀 Netzwerk-Heuristiken Suite - Installation"
echo "=========================================="

# Python-Version prüfen
echo "📍 Prüfe Python-Version..."
python_version=$(python3 --version 2>/dev/null || echo "Nicht gefunden")
if [[ "$python_version" == "Nicht gefunden" ]]; then
    echo "❌ Python 3 ist nicht installiert"
    exit 1
fi
echo "✅ Gefunden: $python_version"

# Pip prüfen
echo "📍 Prüfe pip..."
pip_version=$(pip3 --version 2>/dev/null || echo "Nicht gefunden")
if [[ "$pip_version" == "Nicht gefunden" ]]; then
    echo "❌ pip3 ist nicht installiert"
    exit 1
fi
echo "✅ Gefunden: $pip_version"

# Virtuelle Umgebung erstellen
echo "📍 Erstelle virtuelle Umgebung..."
python3 -m venv venv
if [ $? -eq 0 ]; then
    echo "✅ Virtuelle Umgebung erstellt"
else
    echo "❌ Fehler beim Erstellen der virtuellen Umgebung"
    exit 1
fi

# Virtuelle Umgebung aktivieren
echo "📍 Aktiviere virtuelle Umgebung..."
source venv/bin/activate

# Python-Pakete installieren
echo "📍 Installiere Python-Pakete..."
pip3 install --upgrade pip
pip3 install dnspython requests urllib3

if [ $? -eq 0 ]; then
    echo "✅ Python-Pakete erfolgreich installiert"
else
    echo "❌ Fehler beim Installieren der Python-Pakete"
    exit 1
fi

# Ausführbare Rechte setzen
echo "📍 Setze ausführbare Rechte..."
chmod +x *.py

# Testinstallation
echo "📍 Teste Installation..."
python3 -c "import dns.resolver; import requests; print('✅ Alle Module geladen')"

if [ $? -eq 0 ]; then
    echo "✅ Installation erfolgreich!"
else
    echo "❌ Installation fehlgeschlagen"
    exit 1
fi

# Ergebnis anzeigen
echo ""
echo "🎉 Installation abgeschlossen!"
echo ""
echo "Verwendung:"
echo "  # Virtuelle Umgebung aktivieren"
echo "  source venv/bin/activate"
echo ""
echo "  # Vollständige Analyse durchführen"
echo "  python3 network_heuristics.py example.com"
echo ""
echo "  # DNS-Leak-Test"
echo "  python3 dns_leak_test.py"
echo ""
echo "  # Firewall-Erkennung"
echo "  python3 firewall_detector.py 192.168.1.1"
echo ""
echo "  # Common-Paths-Scan"
echo "  python3 common_paths_scanner.py https://example.com"
echo ""
echo "📖 Siehe README.md für detaillierte Dokumentation"

# Deaktiviere virtuelle Umgebung
deactivate