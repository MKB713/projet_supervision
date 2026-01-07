#!/usr/bin/env python3
"""
Application principale - Plateforme de Supervision Réseau
"""

import sys
import os
import argparse
from pathlib import Path

# Ajouter le dossier src au path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description='Plateforme de Supervision Réseau')
    parser.add_argument('--gui', action='store_true', help='Lancer l\'interface graphique')
    parser.add_argument('--cli', action='store_true', help='Lancer en mode ligne de commande')
    parser.add_argument('--test', action='store_true', help='Lancer les tests')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("   PLATEFORME DE SUPERVISION RÉSEAU")
    print("=" * 60)
    print(f"Python: {sys.version}")
    print(f"Répertoire: {os.getcwd()}")
    print()
    
    # Vérifier l'environnement virtuel
    if 'VIRTUAL_ENV' in os.environ:
        print(f"✅ Environnement virtuel: {os.environ['VIRTUAL_ENV']}")
    else:
        print("⚠️  Environnement virtuel non activé")
        print("   Activez-le: source venv/bin/activate")
    
    # Mode d'exécution
    if args.gui:
        launch_gui()
    elif args.cli:
        launch_cli()
    elif args.test:
        launch_tests()
    else:
        # Mode interactif
        print("Choisissez un mode d'exécution:")
        print("  1. Interface graphique (GUI)")
        print("  2. Ligne de commande (CLI)")
        print("  3. Tests")
        print("  4. Quitter")
        
        choice = input("\nVotre choix [1-4]: ").strip()
        
        if choice == '1':
            launch_gui()
        elif choice == '2':
            launch_cli()
        elif choice == '3':
            launch_tests()
        else:
            print("Au revoir!")
            sys.exit(0)

def launch_gui():
    """Lancer l'interface graphique"""
    print("\n🚀 Lancement de l'interface graphique...")
    
    try:
        # Essayer d'abord l'interface simple
        from gui.simple_gui import main as gui_main
        gui_main()
        
    except ImportError as e:
        print(f"❌ Erreur d'importation: {e}")
        print("Création d'une interface graphique de secours...")
        create_fallback_gui()
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()

def create_fallback_gui():
    """Créer une interface graphique de secours"""
    import sys  # Ajout de l'import sys
    
    try:
        from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, 
                                   QVBoxLayout, QLabel, QPushButton, 
                                   QTextEdit, QMessageBox)
        from PyQt5.QtCore import Qt
        
        class FallbackWindow(QMainWindow):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("Supervision Réseau - Mode Simple")
                self.setGeometry(100, 100, 600, 400)
                
                central = QWidget()
                self.setCentralWidget(central)
                
                layout = QVBoxLayout()
                
                # Titre
                title = QLabel("🔧 Plateforme de Supervision Réseau")
                title.setAlignment(Qt.AlignCenter)
                title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
                layout.addWidget(title)
                
                # Message
                message = QLabel(
                    "L'interface graphique complète n'est pas encore disponible.\n"
                    "Utilisez le mode ligne de commande (CLI) pour le moment."
                )
                message.setAlignment(Qt.AlignCenter)
                layout.addWidget(message)
                
                # Boutons
                cli_btn = QPushButton("📟 Lancer le mode CLI")
                cli_btn.clicked.connect(self.launch_cli)
                cli_btn.setStyleSheet("padding: 10px; font-weight: bold;")
                
                test_btn = QPushButton("🧪 Tester la connexion")
                test_btn.clicked.connect(self.run_tests)
                
                layout.addWidget(cli_btn)
                layout.addWidget(test_btn)
                layout.addStretch()
                
                central.setLayout(layout)
            
            def launch_cli(self):
                """Lancer le mode CLI"""
                self.close()
                launch_cli()
            
            def run_tests(self):
                """Exécuter les tests"""
                QMessageBox.information(self, "Tests", 
                    "Pour tester:\n\n"
                    "1. SNMP: python -c \"from core.snmp_manager import SNMPManager; "
                    "m = SNMPManager(); print(m.get_system_info('10.158.68.201'))\"\n\n"
                    "2. Nagios: http://10.158.68.200/nagios4\n"
                    "   Login: nagiosadmin\n"
                    "   Password: admin123")
        
        app = QApplication(sys.argv)  # Correction appliquée ici
        window = FallbackWindow()
        window.show()
        app.exec_()
        
    except ImportError as e:
        print(f"❌ PyQt5 non disponible: {e}")
        print("📟 Lancement automatique du mode CLI...")
        launch_cli()
    except Exception as e:
        print(f"❌ Erreur lors de la création de l'interface: {e}")
        import traceback
        traceback.print_exc()
        print("📟 Lancement automatique du mode CLI...")
        launch_cli()

def launch_cli():
    """Lancer en mode ligne de commande"""
    print("\n📟 Lancement du mode ligne de commande...")
    
    try:
        from core.snmp_manager import SNMPManager
        from core.nagios_client import NagiosClient
        
        # Initialiser les composants
        snmp_manager = SNMPManager(community='supervision')
        nagios_client = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        
        # Menu interactif
        while True:
            print("\n" + "=" * 40)
            print("MENU PRINCIPAL - SUPERVISION RÉSEAU")
            print("=" * 40)
            print("1. Découvrir les équipements")
            print("2. Vérifier le statut Nagios")
            print("3. Surveiller un équipement")
            print("4. Capturer le trafic réseau")
            print("5. Quitter")
            print("=" * 40)
            
            choice = input("\nVotre choix [1-5]: ").strip()
            
            if choice == '1':
                print("\n🔍 Découverte des équipements...")
                devices = snmp_manager.discover_devices()
                if devices:
                    print(f"\n✅ {len(devices)} équipement(s) trouvé(s):")
                    for device in devices:
                        print(f"\n   📍 {device['ip']}")
                        print(f"      Nom: {device['name']}")
                        print(f"      Statut: {device['status']}")
                        print(f"      Description: {device['description']}")
                else:
                    print("❌ Aucun équipement trouvé")
                    
            elif choice == '2':
                print("\n⚠️  Vérification du statut Nagios...")
                if nagios_client.test_connection():
                    print("✅ Nagios est accessible")
                    
                    hosts = nagios_client.get_host_status()
                    if hosts:
                        print(f"\n📊 {len(hosts)} hôte(s) surveillé(s):")
                        for host in hosts[:5]:  # Limiter à 5
                            status_map = {0: "✅", 1: "⚠️", 2: "❌", 3: "❓"}
                            icon = status_map.get(host['status'], "❓")
                            print(f"   {icon} {host['name']}: {host['status_text']}")
                    else:
                        print("ℹ️  Aucun hôte trouvé")
                else:
                    print("❌ Nagios n'est pas accessible")
                    
            elif choice == '3':
                ip = input("Adresse IP à surveiller (ex: 10.158.68.201): ").strip()
                if ip:
                    print(f"\n📡 Surveillance de {ip}...")
                    try:
                        info = snmp_manager.get_system_info(ip)
                        print(f"\n📊 Informations système:")
                        for key, value in info.items():
                            print(f"   {key}: {value}")
                    except Exception as e:
                        print(f"❌ Erreur: {e}")
                else:
                    print("❌ Adresse IP invalide")
                    
            elif choice == '4':
                print("\n📊 Capture réseau (à implémenter)...")
                print("Cette fonctionnalité sera disponible dans la version 2.0")
                
            elif choice == '5':
                print("\n👋 Au revoir!")
                break
                
            else:
                print("❌ Choix invalide")
                
    except ImportError as e:
        print(f"❌ Erreur d'importation: {e}")
    except KeyboardInterrupt:
        print("\n\n👋 Interruption par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()

def launch_tests():
    """Lancer les tests"""
    print("\n🧪 Lancement des tests...")
    
    try:
        # Test SNMP Manager
        print("1. Test du module SNMP...")
        from core.snmp_manager import SNMPManager
        snmp = SNMPManager()
        
        # Test avec le switch
        test_ip = "10.158.68.201"
        info = snmp.get_system_info(test_ip)
        if 'sysName' in info:
            print(f"   ✅ SNMP fonctionnel sur {test_ip}")
            print(f"      Hostname: {info.get('sysName', 'N/A')}")
        else:
            print(f"   ❌ SNMP échoué sur {test_ip}")
        
        # Test Nagios Client
        print("\n2. Test du client Nagios...")
        from core.nagios_client import NagiosClient
        nagios = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        
        if nagios.test_connection():
            print("   ✅ Connexion Nagios réussie")
            hosts = nagios.get_host_status()
            print(f"      {len(hosts)} hôte(s) trouvé(s)")
        else:
            print("   ❌ Connexion Nagios échouée")
        
        print("\n✅ Tous les tests terminés!")
        
    except Exception as e:
        print(f"❌ Erreur lors des tests: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()