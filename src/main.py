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
        elif choice == '4':
            print("\n📊 Capture réseau...")
            from core.packet_analyzer import PacketAnalyzer
            
            analyzer = PacketAnalyzer()
            
            print("Interfaces disponibles:")
            interfaces = analyzer.list_interfaces()
            for iface in interfaces:
                print(f"  • {iface['name']} ({iface['state']})")
            
            interface = input("\nInterface [lo]: ").strip() or 'lo'
            analyzer.interface = interface
            
            print(f"\nCapture sur {interface}...")
            analyzer.start_capture(packet_count=20, timeout=5)
            
            import time
            time.sleep(6)
            
            analyzer.stop_capture()
            
            print(f"\n✅ {len(analyzer.get_packets())} paquets capturés")
            
            stats = analyzer.get_statistics()
            print(f"   Bytes: {stats.get('total_bytes', 0)}")
            print(f"   Protocoles: {len(stats.get('protocols', {}))}")
        else:
            print("Au revoir!")
            sys.exit(0)

def launch_gui():
    """Lancer l'interface graphique"""
    print("\n🚀 Lancement de l'interface graphique...")
    
    try:
        from PyQt5.QtWidgets import QApplication
        from gui.main_window import MainWindow
        
        app = QApplication(sys.argv)
        app.setStyle('Fusion')  # Style moderne
        
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec_())
        
    except ImportError as e:
        print(f"❌ Erreur d'importation: {e}")
        print("Installez les dépendances: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()

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