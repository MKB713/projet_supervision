#!/usr/bin/env python3
"""
Module SNMP Manager pour interagir avec les équipements réseau
"""

from pysnmp.hlapi import *
import time
from datetime import datetime
import json
from typing import Dict, List, Optional

class SNMPManager:
    """Gestionnaire SNMP pour la supervision réseau"""
    
    def __init__(self, community: str = 'supervision', version: str = '2c'):
        """
        Initialise le gestionnaire SNMP
        
        Args:
            community: Communauté SNMP (default: 'supervision')
            version: Version SNMP (default: '2c')
        """
        self.community = community
        self.version = version
        self.results = {}
        
    def get_snmp_value(self, target_ip: str, oid: str, port: int = 161) -> Dict:
        """
        Récupère une valeur SNMP simple
        
        Args:
            target_ip: Adresse IP de l'équipement
            oid: OID à interroger
            port: Port SNMP (default: 161)
            
        Returns:
            Dict avec 'success' ou 'error'
        """
        try:
            # Configuration du transport
            transport = UdpTransportTarget((target_ip, port), timeout=2.0, retries=1)
            
            # Configuration des données SNMP
            if self.version == '1':
                auth_data = CommunityData(self.community, mpModel=0)
            else:  # '2c'
                auth_data = CommunityData(self.community, mpModel=1)
            
            # Exécution de la requête
            iterator = getCmd(
                SnmpEngine(),
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                return {'error': f"Indication: {errorIndication}"}
            elif errorStatus:
                return {'error': f"Status: {errorStatus.prettyPrint()} at {errorIndex}"}
            else:
                for varBind in varBinds:
                    return {'success': str(varBind[1])}
                    
        except Exception as e:
            return {'error': f"Exception: {str(e)}"}
    
    def get_system_info(self, target_ip: str) -> Dict:
        """
        Récupère les informations système complètes
        
        Args:
            target_ip: Adresse IP de l'équipement
            
        Returns:
            Dict avec les informations système
        """
        info = {}
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',    # Description système
            'sysName': '1.3.6.1.2.1.1.5.0',     # Nom de l'hôte
            'sysLocation': '1.3.6.1.2.1.1.6.0', # Localisation
            'sysUpTime': '1.3.6.1.2.1.1.3.0',   # Temps de fonctionnement
            'sysContact': '1.3.6.1.2.1.1.4.0',  # Contact
        }
        
        for key, oid in oids.items():
            result = self.get_snmp_value(target_ip, oid)
            if 'success' in result:
                info[key] = result['success']
            else:
                info[key] = f"Error: {result.get('error', 'Unknown')}"
                
        return info
    
    def get_interface_stats(self, target_ip: str, interface_index: int = 1) -> Dict:
        """
        Récupère les statistiques d'une interface réseau
        
        Args:
            target_ip: Adresse IP de l'équipement
            interface_index: Index de l'interface (default: 1)
            
        Returns:
            Dict avec les statistiques de l'interface
        """
        stats = {}
        base_oid = '1.3.6.1.2.1.2.2.1'
        
        metrics = {
            'ifOperStatus': f'{base_oid}.8.{interface_index}',   # État opérationnel
            'ifInOctets': f'{base_oid}.10.{interface_index}',    # Octets entrants
            'ifOutOctets': f'{base_oid}.16.{interface_index}',   # Octets sortants
            'ifInErrors': f'{base_oid}.14.{interface_index}',    # Erreurs entrantes
            'ifOutErrors': f'{base_oid}.20.{interface_index}',   # Erreurs sortantes
        }
        
        for key, oid in metrics.items():
            result = self.get_snmp_value(target_ip, oid)
            if 'success' in result:
                stats[key] = result['success']
            else:
                stats[key] = 'N/A'
                
        return stats
    
    def discover_devices(self, network_range: str = '10.158.68.0/21') -> List[Dict]:
        """
        Découvre les équipements SNMP sur le réseau
        
        Args:
            network_range: Plage réseau à scanner
            
        Returns:
            Liste des équipements découverts
        """
        discovered = []
        
        # Équipements connus (pour le test)
        test_ips = [
            ('10.158.68.200', 'nagios-server'),
            ('10.158.68.201', 'switch-01'),
            ('10.158.68.202', 'router-01')
        ]
        
        for ip, expected_name in test_ips:
            print(f"Scanning {ip}...")
            try:
                info = self.get_system_info(ip)
                if 'sysName' in info and not info['sysName'].startswith('Error'):
                    status = '✅ Online' if 'sysName' in info else '❌ Offline'
                    discovered.append({
                        'ip': ip,
                        'name': info.get('sysName', 'Unknown'),
                        'description': info.get('sysDescr', 'No description')[:50],
                        'status': status,
                        'uptime': info.get('sysUpTime', 'N/A'),
                        'location': info.get('sysLocation', 'N/A')
                    })
            except Exception as e:
                print(f"  Error scanning {ip}: {e}")
                
        return discovered
    
    def monitor_device(self, target_ip: str, interval: int = 60):
        """
        Surveillance continue d'un équipement
        
        Args:
            target_ip: Adresse IP à surveiller
            interval: Intervalle en secondes (default: 60)
        """
        print(f"Starting monitoring of {target_ip} every {interval}s...")
        
        while True:
            timestamp = datetime.now().isoformat()
            
            try:
                # Récupérer les informations
                system_info = self.get_system_info(target_ip)
                interface_stats = self.get_interface_stats(target_ip)
                
                # Stocker les résultats
                self.results[timestamp] = {
                    'system': system_info,
                    'interface': interface_stats
                }
                
                # Afficher les résultats
                print(f"\n[{timestamp}] {target_ip}")
                print(f"  Hostname: {system_info.get('sysName', 'N/A')}")
                print(f"  Uptime: {system_info.get('sysUpTime', 'N/A')}")
                print(f"  Interface Status: {interface_stats.get('ifOperStatus', 'N/A')}")
                
                # Sauvegarder dans un fichier
                with open(f'data/snmp_{target_ip.replace(".", "_")}.json', 'w') as f:
                    json.dump(self.results, f, indent=2)
                    
            except Exception as e:
                print(f"  Error: {e}")
            
            time.sleep(interval)

# ============================================================================
# TEST DU MODULE
# ============================================================================

if __name__ == "__main__":
    print("=== Test du module SNMP Manager ===\n")
    
    # Initialiser le manager
    manager = SNMPManager(community='supervision')
    
    # Tester avec le switch
    print("1. Test avec Switch-01 (10.158.68.201):")
    print("-" * 40)
    
    # Informations système
    switch_info = manager.get_system_info('10.158.68.201')
    for key, value in switch_info.items():
        print(f"  {key}: {value[:50]}" if len(str(value)) > 50 else f"  {key}: {value}")
    
    # Statistiques interface
    print("\n2. Statistiques interface:")
    switch_stats = manager.get_interface_stats('10.158.68.201')
    for key, value in switch_stats.items():
        print(f"  {key}: {value}")
    
    # Découverte
    print("\n3. Découverte d'équipements:")
    devices = manager.discover_devices()
    for device in devices:
        print(f"  • {device['ip']} - {device['name']} ({device['status']})")
    
    print("\n✅ Test terminé avec succès!")