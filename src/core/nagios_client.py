#!/usr/bin/env python3
"""
Client Nagios pour interagir avec le serveur Nagios
"""

import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

class NagiosClient:
    """Client pour interagir avec l'API Nagios"""
    
    def __init__(self, base_url: str, username: str, password: str):
        """
        Initialise le client Nagios
        
        Args:
            base_url: URL de base de Nagios (ex: http://10.158.68.200)
            username: Nom d'utilisateur Nagios
            password: Mot de passe Nagios
        """
        self.base_url = base_url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({'User-Agent': 'Network-Supervisor/1.0'})
    
    def test_connection(self) -> bool:
        """
        Teste la connexion à Nagios
        
        Returns:
            bool: True si la connexion réussit
        """
        try:
            response = self.session.get(f"{self.base_url}/nagios4", timeout=5)
            return response.status_code in [200, 401]
        except:
            return False
    
    def get_host_status(self) -> List[Dict]:
        """
        Récupère le statut de tous les hôtes
        
        Returns:
            Liste des hôtes avec leur statut
        """
        try:
            # Utiliser l'interface JSON de Nagios
            url = f"{self.base_url}/nagios4/cgi-bin/statusjson.cgi"
            params = {
                'query': 'hostlist',
                'formatoptions': 'whitespace',
                'details': 'true'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            hosts = []
            
            if 'data' in data and 'hostlist' in data['data']:
                for host_name, host_info in data['data']['hostlist'].items():
                    hosts.append({
                        'name': host_name,
                        'status': host_info.get('current_state', 'UNKNOWN'),
                        'status_text': host_info.get('status_text', ''),
                        'last_check': host_info.get('last_check', ''),
                        'address': host_info.get('address', '')
                    })
            
            return hosts
            
        except Exception as e:
            print(f"Error getting host status: {e}")
            return []
    
    def get_service_status(self, host_name: str = None) -> List[Dict]:
        """
        Récupère le statut des services
        
        Args:
            host_name: Nom de l'hôte (optionnel)
            
        Returns:
            Liste des services avec leur statut
        """
        try:
            url = f"{self.base_url}/nagios4/cgi-bin/statusjson.cgi"
            params = {
                'query': 'servicelist',
                'hostname': host_name if host_name else 'all',
                'formatoptions': 'whitespace'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            services = []
            
            if 'data' in data and 'servicelist' in data['data']:
                for host, host_services in data['data']['servicelist'].items():
                    for service_name, service_info in host_services.items():
                        services.append({
                            'host': host,
                            'service': service_name,
                            'status': service_info.get('current_state', 3),
                            'status_text': service_info.get('status_text', ''),
                            'last_check': service_info.get('last_check', ''),
                            'plugin_output': service_info.get('plugin_output', '')
                        })
            
            return services
            
        except Exception as e:
            print(f"Error getting service status: {e}")
            return []
    
    def get_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Récupère les alertes récentes
        
        Args:
            hours: Nombre d'heures à regarder en arrière
            
        Returns:
            Liste des alertes
        """
        try:
            url = f"{self.base_url}/nagios4/cgi-bin/archivejson.cgi"
            params = {
                'query': 'alertlist',
                'endtime': 'now',
                'starttime': f'-{hours}h'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            alerts = data.get('data', {}).get('alertlist', [])
            
            return alerts
            
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def get_performance_data(self, host: str, service: str) -> Optional[Dict]:
        """
        Récupère les données de performance
        
        Args:
            host: Nom de l'hôte
            service: Nom du service
            
        Returns:
            Données de performance ou None
        """
        try:
            url = f"{self.base_url}/nagios4/cgi-bin/extinfo.cgi"
            params = {
                'type': '2',
                'host': host,
                'service': service
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            # Parsing HTML simplifié
            content = response.text
            if 'Performance Data' in content:
                return {'available': True, 'raw_data': content}
            else:
                return {'available': False}
                
        except Exception as e:
            print(f"Error getting performance data: {e}")
            return None

# ============================================================================
# TEST DU MODULE
# ============================================================================

if __name__ == "__main__":
    print("=== Test du client Nagios ===\n")
    
    # Configuration
    client = NagiosClient(
        base_url="http://10.158.68.200",
        username="nagiosadmin",
        password="admin123"
    )
    
    # Test de connexion
    if client.test_connection():
        print("✅ Connexion à Nagios réussie\n")
        
        # Statut des hôtes
        print("1. Statut des hôtes:")
        hosts = client.get_host_status()
        for host in hosts[:5]:  # Afficher les 5 premiers
            status_icon = "✅" if host['status'] == 0 else "⚠️" if host['status'] == 1 else "❌"
            print(f"   {status_icon} {host['name']} ({host['address']}): {host['status_text']}")
        
        # Statut des services
        print("\n2. Statut des services (Switch-01):")
        services = client.get_service_status('switch-01')
        for service in services:
            status_map = {0: "✅ OK", 1: "⚠️ WARNING", 2: "❌ CRITICAL", 3: "❓ UNKNOWN"}
            status = status_map.get(service['status'], "❓ UNKNOWN")
            print(f"   {status} {service['service']}: {service.get('plugin_output', '')[:50]}")
        
        # Alertes récentes
        print("\n3. Alertes récentes (24h):")
        alerts = client.get_alerts(hours=24)
        if alerts:
            for alert in alerts[:3]:  # Afficher 3 alertes
                print(f"   ⚠️  {alert.get('host_name', 'N/A')}: {alert.get('message', 'N/A')[:50]}")
        else:
            print("   ✅ Aucune alerte récente")
            
    else:
        print("❌ Impossible de se connecter à Nagios")
        print("Vérifiez:")
        print("  1. L'URL: http://10.158.68.200/nagios4")
        print("  2. Les identifiants: nagiosadmin / admin123")
        print("  3. La connectivité réseau")