#!/usr/bin/env python3
"""
Module SNMP Manager pour interagir avec les équipements réseau
Version corrigée avec imports pysnmp 7.x
"""

# Imports SNMP corrigés pour pysnmp 7.x
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd
)
from pysnmp.proto.rfc1902 import Integer, OctetString
import time
from datetime import datetime
import json
from typing import Dict, List, Optional
import asyncio

class SNMPManager:
    """Gestionnaire SNMP pour la supervision réseau"""
    
    def __init__(self, community: str = 'supervision', version: str = '2c', timeout: int = 2):
        """
        Initialise le gestionnaire SNMP
        
        Args:
            community: Communauté SNMP (default: 'supervision')
            version: Version SNMP (default: '2c')
            timeout: Timeout en secondes (default: 2)
        """
        self.community = community
        self.version = version
        self.timeout = timeout
        self.results = {}
        self.engine = SnmpEngine()
        
    def get_snmp_value(self, target_ip: str, oid: str, port: int = 161) -> Dict:
        """
        Récupère une valeur SNMP simple (synchrone)
        
        Args:
            target_ip: Adresse IP de l'équipement
            oid: OID à interroger
            port: Port SNMP (default: 161)
            
        Returns:
            Dict avec 'success' ou 'error'
        """
        try:
            return asyncio.run(self._get_snmp_value_async(target_ip, oid, port))
        except Exception as e:
            return {'error': f"Exception: {str(e)}"}
    
    async def _get_snmp_value_async(self, target_ip: str, oid: str, port: int = 161) -> Dict:
        """
        Récupère une valeur SNMP (asynchrone)
        """
        try:
            transport = UdpTransportTarget((target_ip, port), timeout=self.timeout, retries=1)
            
            if self.version == '1':
                auth_data = CommunityData(self.community, mpModel=0)
            else:
                auth_data = CommunityData(self.community, mpModel=1)
            
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                self.engine,
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            if errorIndication:
                return {'error': f"Indication: {errorIndication}"}
            elif errorStatus:
                return {'error': f"Status: {errorStatus.prettyPrint()} at {errorIndex}"}
            else:
                for varBind in varBinds:
                    value = varBind[1]
                    if isinstance(value, OctetString):
                        try:
                            return {'success': value.prettyPrint()}
                        except:
                            return {'success': str(value)}
                    else:
                        return {'success': str(value)}
                        
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
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
        }
        
        for key, oid in oids.items():
            result = self.get_snmp_value(target_ip, oid)
            if 'success' in result:
                value = result['success']
                if key == 'sysUpTime' and value.isdigit():
                    ticks = int(value)
                    seconds = ticks / 100
                    days = int(seconds // 86400)
                    hours = int((seconds % 86400) // 3600)
                    minutes = int((seconds % 3600) // 60)
                    info[key] = f"{days}j {hours}h {minutes}m"
                else:
                    info[key] = value
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
            'ifOperStatus': f'{base_oid}.8.{interface_index}',
            'ifInOctets': f'{base_oid}.10.{interface_index}',
            'ifOutOctets': f'{base_oid}.16.{interface_index}',
            'ifInErrors': f'{base_oid}.14.{interface_index}',
            'ifOutErrors': f'{base_oid}.20.{interface_index}',
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
                system_info = self.get_system_info(target_ip)
                interface_stats = self.get_interface_stats(target_ip)
                
                self.results[timestamp] = {
                    'system': system_info,
                    'interface': interface_stats
                }
                
                print(f"\n[{timestamp}] {target_ip}")
                print(f"  Hostname: {system_info.get('sysName', 'N/A')}")
                print(f"  Uptime: {system_info.get('sysUpTime', 'N/A')}")
                print(f"  Interface Status: {interface_stats.get('ifOperStatus', 'N/A')}")
                
                import os
                os.makedirs('data', exist_ok=True)
                with open(f'data/snmp_{target_ip.replace(".", "_")}.json', 'w') as f:
                    json.dump(self.results, f, indent=2)
                    
            except Exception as e:
                print(f"  Error: {e}")
            
            time.sleep(interval)

if __name__ == "__main__":
    print("=== Test du module SNMP Manager ===\n")
    
    manager = SNMPManager(community='supervision')
    
    print("1. Test avec Switch-01 (10.158.68.201):")
    print("-" * 40)
    
    switch_info = manager.get_system_info('10.158.68.201')
    for key, value in switch_info.items():
        print(f"  {key}: {value[:50]}" if len(str(value)) > 50 else f"  {key}: {value}")
    
    print("\n2. Statistiques interface:")
    switch_stats = manager.get_interface_stats('10.158.68.201')
    for key, value in switch_stats.items():
        print(f"  {key}: {value}")
    
    print("\n3. Découverte d'équipements:")
    devices = manager.discover_devices()
    for device in devices:
        print(f"  • {device['ip']} - {device['name']} ({device['status']})")
    
    print("\n✅ Test terminé avec succès!")