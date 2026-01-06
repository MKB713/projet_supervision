#!/usr/bin/env python3
"""
Module d'analyse de paquets réseau avec PyShark/TShark
"""

import pyshark
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import threading
import time
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Any
import ipaddress
import socket
import subprocess
import os

class PacketAnalyzer:
    """
    Analyseur de paquets réseau utilisant PyShark (wrapper autour de TShark)
    """
    
    def __init__(self, interface: str = None):
        """
        Initialise l'analyseur de paquets
        
        Args:
            interface: Interface réseau à capturer (si None, détection automatique)
        """
        self.interface = interface or self.detect_interface()
        self.capture = None
        self.is_capturing = False
        self.capture_thread = None
        self.packets = []
        self.statistics = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'sent': 0, 'received': 0, 'bytes': 0})
        self.conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        # Fichiers de capture
        self.capture_file = None
        self.capture_start_time = None
        
        # Détection des services courants
        self.common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            161: 'SNMP',
            162: 'SNMP Trap',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
    def detect_interface(self) -> str:
        """
        Détecte automatiquement l'interface réseau à utiliser
        
        Returns:
            Nom de l'interface
        """
        try:
            # Liste des interfaces disponibles
            result = subprocess.run(['tshark', '-D'], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=5)
            
            if result.returncode == 0:
                interfaces = result.stdout.strip().split('\n')
                for interface in interfaces:
                    if interface.strip():
                        # Préférer les interfaces actives (pas lo)
                        iface_name = interface.split('.')[1].strip() if '.' in interface else interface.strip()
                        if iface_name != 'lo' and not iface_name.startswith('bluetooth'):
                            return iface_name
            
            # Fallback sur loopback
            return 'lo'
            
        except Exception as e:
            print(f"Erreur détection interface: {e}")
            return 'lo'
    
    def list_interfaces(self) -> List[Dict[str, str]]:
        """
        Liste toutes les interfaces réseau disponibles
        
        Returns:
            Liste des interfaces avec informations
        """
        interfaces = []
        try:
            result = subprocess.run(['ip', 'addr', 'show'], 
                                   capture_output=True, 
                                   text=True)
            
            current_iface = None
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith(' '):
                    # Nouvelle interface
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_iface = parts[1].strip()
                        interfaces.append({
                            'name': current_iface,
                            'state': 'UP' if 'UP' in line else 'DOWN',
                            'ip_addresses': [],
                            'mac': None
                        })
                elif current_iface and 'inet ' in line:
                    # Adresse IP
                    ip_parts = line.strip().split()
                    if len(ip_parts) >= 2:
                        ip = ip_parts[1].split('/')[0]
                        interfaces[-1]['ip_addresses'].append(ip)
                elif current_iface and 'link/ether' in line:
                    # Adresse MAC
                    mac_parts = line.strip().split()
                    if len(mac_parts) >= 2:
                        interfaces[-1]['mac'] = mac_parts[1]
            
            return [iface for iface in interfaces if iface['name'] != 'lo']
            
        except Exception as e:
            print(f"Erreur liste interfaces: {e}")
            return []
    
    def start_capture(self, 
                     packet_count: int = 100, 
                     timeout: int = 30,
                     display_filter: str = '',
                     output_file: str = None) -> bool:
        """
        Démarre une capture de paquets
        
        Args:
            packet_count: Nombre maximum de paquets à capturer
            timeout: Timeout en secondes
            display_filter: Filtre d'affichage TShark
            output_file: Fichier de sortie PCAP (optionnel)
            
        Returns:
            True si la capture a démarré
        """
        try:
            # Nettoyer les anciennes données
            self.packets.clear()
            self.statistics.clear()
            self.protocol_stats.clear()
            self.ip_stats.clear()
            self.conversations.clear()
            
            # Configuration de la capture
            capture_params = {
                'interface': self.interface,
                'display_filter': display_filter,
                'use_json': True,
                'include_raw': False,
                'output_file': output_file,
                'custom_parameters': ['-l']  # Flush après chaque paquet
            }
            
            # Créer l'objet de capture
            self.capture = pyshark.LiveCapture(**capture_params)
            
            # Fichier de capture
            if output_file:
                self.capture_file = output_file
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.capture_file = f"captures/capture_{timestamp}.pcap"
                os.makedirs('captures', exist_ok=True)
            
            self.capture_start_time = datetime.now()
            self.is_capturing = True
            
            # Démarrer la capture dans un thread séparé
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(packet_count, timeout),
                daemon=True
            )
            self.capture_thread.start()
            
            print(f"✅ Capture démarrée sur {self.interface}")
            print(f"   Filtre: {display_filter or 'Aucun'}")
            print(f"   Max paquets: {packet_count}")
            print(f"   Fichier: {self.capture_file}")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur démarrage capture: {e}")
            return False
    
    def _capture_packets(self, packet_count: int, timeout: int):
        """
        Capture les paquets (exécuté dans un thread)
        """
        try:
            start_time = datetime.now()
            packet_counter = 0
            
            for packet in self.capture.sniff_continuously(packet_count=packet_count):
                if not self.is_capturing:
                    break
                
                # Convertir le paquet en dictionnaire
                packet_dict = self._packet_to_dict(packet)
                self.packets.append(packet_dict)
                
                # Mettre à jour les statistiques
                self._update_statistics(packet_dict)
                
                packet_counter += 1
                
                # Vérifier le timeout
                if (datetime.now() - start_time).seconds > timeout:
                    print(f"⏱️  Timeout atteint ({timeout}s)")
                    break
                    
                if packet_counter >= packet_count:
                    print(f"✅ Nombre maximum de paquets atteint ({packet_count})")
                    break
                    
        except Exception as e:
            print(f"Erreur capture: {e}")
        finally:
            self.is_capturing = False
            if self.capture:
                self.capture.close()
            print("🛑 Capture arrêtée")
    
    def _packet_to_dict(self, packet) -> Dict[str, Any]:
        """
        Convertit un paquet PyShark en dictionnaire
        
        Args:
            packet: Paquet PyShark
            
        Returns:
            Dictionnaire avec les informations du paquet
        """
        packet_data = {
            'timestamp': str(packet.sniff_time),
            'timestamp_epoch': packet.sniff_timestamp,
            'length': int(packet.length) if hasattr(packet, 'length') else 0,
            'protocols': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN',
            'frame_number': int(packet.number) if hasattr(packet, 'number') else 0,
            'captured_length': int(packet.captured_length) if hasattr(packet, 'captured_length') else 0
        }
        
        # Adresses IP (IPv4 et IPv6)
        if hasattr(packet, 'ip'):
            packet_data['src_ip'] = packet.ip.src
            packet_data['dst_ip'] = packet.ip.dst
            packet_data['protocol'] = packet.ip.proto if hasattr(packet.ip, 'proto') else 'IP'
            
        elif hasattr(packet, 'ipv6'):
            packet_data['src_ip'] = packet.ipv6.src
            packet_data['dst_ip'] = packet.ipv6.dst
            packet_data['protocol'] = 'IPv6'
        
        # Adresses MAC
        if hasattr(packet, 'eth'):
            packet_data['src_mac'] = packet.eth.src if hasattr(packet.eth, 'src') else ''
            packet_data['dst_mac'] = packet.eth.dst if hasattr(packet.eth, 'dst') else ''
        
        # Ports TCP
        if hasattr(packet, 'tcp'):
            packet_data['src_port'] = int(packet.tcp.srcport)
            packet_data['dst_port'] = int(packet.tcp.dstport)
            packet_data['protocol'] = 'TCP'
            
            # Informations TCP supplémentaires
            tcp_info = {}
            if hasattr(packet.tcp, 'flags'):
                tcp_info['flags'] = packet.tcp.flags
            if hasattr(packet.tcp, 'seq'):
                tcp_info['seq'] = packet.tcp.seq
            if hasattr(packet.tcp, 'ack'):
                tcp_info['ack'] = packet.tcp.ack
            if hasattr(packet.tcp, 'window_size'):
                tcp_info['window'] = packet.tcp.window_size
            
            packet_data['tcp_info'] = tcp_info
            
            # Détection du service
            port = packet_data['dst_port']
            if port in self.common_ports:
                packet_data['service'] = self.common_ports[port]
            elif packet_data['src_port'] in self.common_ports:
                packet_data['service'] = self.common_ports[packet_data['src_port']]
        
        # Ports UDP
        elif hasattr(packet, 'udp'):
            packet_data['src_port'] = int(packet.udp.srcport)
            packet_data['dst_port'] = int(packet.udp.dstport)
            packet_data['protocol'] = 'UDP'
            
            # Détection du service
            port = packet_data['dst_port']
            if port in self.common_ports:
                packet_data['service'] = self.common_ports[port]
        
        # ICMP
        elif hasattr(packet, 'icmp'):
            packet_data['protocol'] = 'ICMP'
            if hasattr(packet.icmp, 'type'):
                packet_data['icmp_type'] = packet.icmp.type
            if hasattr(packet.icmp, 'code'):
                packet_data['icmp_code'] = packet.icmp.code
        
        # DNS
        elif hasattr(packet, 'dns'):
            packet_data['protocol'] = 'DNS'
            if hasattr(packet.dns, 'qry_name'):
                packet_data['dns_query'] = packet.dns.qry_name
            if hasattr(packet.dns, 'resp_name'):
                packet_data['dns_response'] = packet.dns.resp_name
        
        # HTTP
        elif hasattr(packet, 'http'):
            packet_data['protocol'] = 'HTTP'
            if hasattr(packet.http, 'request_method'):
                packet_data['http_method'] = packet.http.request_method
                packet_data['http_uri'] = packet.http.request_uri if hasattr(packet.http, 'request_uri') else ''
            elif hasattr(packet.http, 'response_code'):
                packet_data['http_code'] = packet.http.response_code
        
        # SNMP
        elif hasattr(packet, 'snmp'):
            packet_data['protocol'] = 'SNMP'
            if hasattr(packet.snmp, 'community'):
                packet_data['snmp_community'] = packet.snmp.community
        
        return packet_data
    
    def _update_statistics(self, packet_dict: Dict):
        """
        Met à jour les statistiques de capture
        """
        # Statistiques générales
        self.statistics['total_packets'] += 1
        self.statistics['total_bytes'] += packet_dict.get('length', 0)
        
        # Statistiques par protocole
        protocol = packet_dict.get('protocol', 'Other')
        self.protocol_stats[protocol] += 1
        
        # Statistiques par IP
        src_ip = packet_dict.get('src_ip')
        dst_ip = packet_dict.get('dst_ip')
        
        if src_ip:
            self.ip_stats[src_ip]['sent'] += 1
            self.ip_stats[src_ip]['bytes'] += packet_dict.get('length', 0)
        
        if dst_ip:
            self.ip_stats[dst_ip]['received'] += 1
            self.ip_stats[dst_ip]['bytes'] += packet_dict.get('length', 0)
        
        # Conversations
        if src_ip and dst_ip:
            conv_key = f"{src_ip} -> {dst_ip}"
            self.conversations[conv_key]['packets'] += 1
            self.conversations[conv_key]['bytes'] += packet_dict.get('length', 0)
        
        # Service detection
        service = packet_dict.get('service')
        if service:
            self.statistics[f'service_{service}'] = self.statistics.get(f'service_{service}', 0) + 1
    
    def stop_capture(self):
        """Arrête la capture en cours"""
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
    
    def get_capture_status(self) -> Dict[str, Any]:
        """
        Retourne le statut de la capture
        
        Returns:
            Dictionnaire avec le statut
        """
        duration = 0
        if self.capture_start_time:
            duration = (datetime.now() - self.capture_start_time).total_seconds()
        
        return {
            'is_capturing': self.is_capturing,
            'interface': self.interface,
            'packets_captured': len(self.packets),
            'duration_seconds': duration,
            'start_time': self.capture_start_time.isoformat() if self.capture_start_time else None,
            'capture_file': self.capture_file
        }
    
    def get_packets(self, limit: int = None) -> List[Dict]:
        """
        Retourne les paquets capturés
        
        Args:
            limit: Limite du nombre de paquets à retourner
            
        Returns:
            Liste des paquets
        """
        if limit:
            return self.packets[-limit:]
        return self.packets
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retourne les statistiques complètes de la capture
        
        Returns:
            Dictionnaire des statistiques
        """
        stats = dict(self.statistics)
        
        # Ajouter les statistiques de protocoles
        stats['protocols'] = dict(self.protocol_stats)
        
        # Ajouter le débit
        if self.capture_start_time:
            duration = (datetime.now() - self.capture_start_time).total_seconds()
            if duration > 0:
                stats['bytes_per_second'] = stats['total_bytes'] / duration
                stats['packets_per_second'] = stats['total_packets'] / duration
        
        # Top 10 des IPs
        top_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['sent'] + x[1]['received'],
            reverse=True
        )[:10]
        stats['top_ips'] = {ip: data for ip, data in top_ips}
        
        # Top 10 des conversations
        top_conversations = sorted(
            self.conversations.items(),
            key=lambda x: x[1]['packets'],
            reverse=True
        )[:10]
        stats['top_conversations'] = {conv: data for conv, data in top_conversations}
        
        return stats
    
    def analyze_traffic_patterns(self) -> Dict[str, Any]:
        """
        Analyse les patterns de trafic
        
        Returns:
            Analyse détaillée du trafic
        """
        if not self.packets:
            return {}
        
        df = pd.DataFrame(self.packets)
        analysis = {}
        
        # Conversion des timestamps
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
        
        # 1. Distribution temporelle
        if not df.empty:
            time_analysis = {}
            
            # Paquets par seconde
            if len(df) > 1:
                packets_per_sec = df.resample('1S').size()
                time_analysis['packets_per_second'] = {
                    'mean': float(packets_per_sec.mean()),
                    'max': float(packets_per_sec.max()),
                    'min': float(packets_per_sec.min()),
                    'std': float(packets_per_sec.std())
                }
            
            # Bytes par seconde
            if 'length' in df.columns:
                bytes_per_sec = df['length'].resample('1S').sum()
                time_analysis['bytes_per_second'] = {
                    'mean': float(bytes_per_sec.mean()),
                    'max': float(bytes_per_sec.max()),
                    'min': float(bytes_per_sec.min()),
                    'total': float(bytes_per_sec.sum())
                }
            
            analysis['time_distribution'] = time_analysis
        
        # 2. Top sources et destinations
        if 'src_ip' in df.columns:
            top_sources = df['src_ip'].value_counts().head(10).to_dict()
            analysis['top_sources'] = top_sources
        
        if 'dst_ip' in df.columns:
            top_destinations = df['dst_ip'].value_counts().head(10).to_dict()
            analysis['top_destinations'] = top_destinations
        
        # 3. Distribution des protocoles
        if 'protocol' in df.columns:
            protocol_dist = df['protocol'].value_counts().to_dict()
            analysis['protocol_distribution'] = protocol_dist
        
        # 4. Ports les plus utilisés
        port_columns = ['src_port', 'dst_port']
        for col in port_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                top_ports = df[col].dropna().astype(int).value_counts().head(10).to_dict()
                analysis[f'top_{col}'] = top_ports
        
        # 5. Détection d'anomalies
        anomalies = self._detect_anomalies(df)
        if anomalies:
            analysis['anomalies'] = anomalies
        
        # 6. Services détectés
        if 'service' in df.columns:
            services = df['service'].dropna().value_counts().to_dict()
            analysis['services'] = services
        
        return analysis
    
    def _detect_anomalies(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Détecte les anomalies dans le trafic
        
        Args:
            df: DataFrame des paquets
            
        Returns:
            Anomalies détectées
        """
        anomalies = {}
        
        # Détection de scan de ports
        if 'dst_port' in df.columns and 'src_ip' in df.columns:
            port_scan_threshold = 20  # Paquets vers différents ports depuis une IP
            src_ip_groups = df.groupby('src_ip')['dst_port'].nunique()
            potential_scanners = src_ip_groups[src_ip_groups > port_scan_threshold]
            
            if not potential_scanners.empty:
                anomalies['port_scans'] = potential_scanners.to_dict()
        
        # Détection de flood
        if len(df) > 100:  # Au moins 100 paquets pour l'analyse
            packets_per_sec = df.resample('1S').size()
            flood_threshold = packets_per_sec.mean() + 3 * packets_per_sec.std()
            flood_periods = packets_per_sec[packets_per_sec > flood_threshold]
            
            if not flood_periods.empty:
                anomalies['potential_floods'] = {
                    'threshold': float(flood_threshold),
                    'periods': flood_periods.index.strftime('%H:%M:%S').tolist(),
                    'max_rate': float(flood_periods.max())
                }
        
        # Détection de traffic suspect (ports inhabituels)
        suspicious_ports = [4444, 31337, 6667]  # Ports communs pour malware/backdoors
        if 'dst_port' in df.columns:
            suspicious_traffic = df[df['dst_port'].isin(suspicious_ports)]
            if not suspicious_traffic.empty:
                anomalies['suspicious_ports'] = {
                    'ports': suspicious_ports,
                    'count': len(suspicious_traffic),
                    'sources': suspicious_traffic['src_ip'].unique().tolist()
                }
        
        return anomalies
    
    def export_to_csv(self, filename: str = None) -> str:
        """
        Exporte les paquets capturés en CSV
        
        Args:
            filename: Nom du fichier (optionnel)
            
        Returns:
            Chemin du fichier généré
        """
        if not self.packets:
            return None
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"exports/packets_{timestamp}.csv"
        
        os.makedirs('exports', exist_ok=True)
        
        df = pd.DataFrame(self.packets)
        df.to_csv(filename, index=False)
        
        return filename
    
    def export_to_json(self, filename: str = None) -> str:
        """
        Exporte les paquets et statistiques en JSON
        
        Args:
            filename: Nom du fichier (optionnel)
            
        Returns:
            Chemin du fichier généré
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"exports/analysis_{timestamp}.json"
        
        os.makedirs('exports', exist_ok=True)
        
        export_data = {
            'metadata': {
                'capture_date': datetime.now().isoformat(),
                'interface': self.interface,
                'packet_count': len(self.packets),
                'duration': (datetime.now() - self.capture_start_time).total_seconds() if self.capture_start_time else 0
            },
            'statistics': self.get_statistics(),
            'analysis': self.analyze_traffic_patterns(),
            'top_packets': self.packets[:100] if self.packets else []
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def read_pcap_file(self, filename: str) -> bool:
        """
        Lit un fichier PCAP existant
        
        Args:
            filename: Chemin du fichier PCAP
            
        Returns:
            True si la lecture a réussi
        """
        try:
            print(f"📖 Lecture du fichier PCAP: {filename}")
            
            # Nettoyer les anciennes données
            self.packets.clear()
            self.statistics.clear()
            self.protocol_stats.clear()
            self.ip_stats.clear()
            self.conversations.clear()
            
            # Lire le fichier PCAP avec PyShark
            cap = pyshark.FileCapture(filename, use_json=True)
            
            packet_count = 0
            for packet in cap:
                packet_dict = self._packet_to_dict(packet)
                self.packets.append(packet_dict)
                self._update_statistics(packet_dict)
                packet_count += 1
                
                # Limiter pour éviter la mémoire
                if packet_count >= 10000:
                    print(f"⚠️  Limité à 10000 paquets pour la mémoire")
                    break
            
            cap.close()
            
            print(f"✅ Fichier lu: {packet_count} paquets chargés")
            return True
            
        except Exception as e:
            print(f"❌ Erreur lecture PCAP: {e}")
            return False
    
    def get_network_map(self) -> Dict[str, Any]:
        """
        Génère une carte réseau basée sur les paquets capturés
        
        Returns:
            Carte réseau avec les équipements et connexions
        """
        network_map = {
            'devices': {},
            'connections': [],
            'services': {}
        }
        
        # Analyser les équipements
        for ip, stats in self.ip_stats.items():
            try:
                # Essayer de résoudre le nom d'hôte
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                # Déterminer le type d'équipement basé sur les ports
                device_type = 'Unknown'
                if any(port in [80, 443, 8080] for port in self._get_ports_for_ip(ip)):
                    device_type = 'Server'
                elif any(port in [161, 162] for port in self._get_ports_for_ip(ip)):
                    device_type = 'Network Device'
                elif stats['sent'] > stats['received'] * 10:
                    device_type = 'Client'
                
                network_map['devices'][ip] = {
                    'hostname': hostname,
                    'type': device_type,
                    'packets_sent': stats['sent'],
                    'packets_received': stats['received'],
                    'bytes_total': stats['bytes'],
                    'open_ports': self._get_ports_for_ip(ip)
                }
                
            except Exception as e:
                print(f"Erreur analyse équipement {ip}: {e}")
        
        # Analyser les connexions
        for conv, stats in self.conversations.items():
            src, dst = conv.split(' -> ')
            if src in network_map['devices'] and dst in network_map['devices']:
                network_map['connections'].append({
                    'source': src,
                    'destination': dst,
                    'packets': stats['packets'],
                    'bytes': stats['bytes'],
                    'protocols': self._get_protocols_between(src, dst)
                })
        
        # Analyser les services
        if 'service' in [p.get('service') for p in self.packets if p.get('service')]:
            services_df = pd.DataFrame([p for p in self.packets if p.get('service')])
            if not services_df.empty and 'service' in services_df.columns:
                service_stats = services_df['service'].value_counts().to_dict()
                network_map['services'] = service_stats
        
        return network_map
    
    def _get_ports_for_ip(self, ip: str) -> List[int]:
        """Retourne les ports utilisés par une IP"""
        ports = set()
        for packet in self.packets:
            if packet.get('src_ip') == ip and packet.get('src_port'):
                ports.add(packet['src_port'])
            if packet.get('dst_ip') == ip and packet.get('dst_port'):
                ports.add(packet['dst_port'])
        return list(ports)
    
    def _get_protocols_between(self, ip1: str, ip2: str) -> List[str]:
        """Retourne les protocoles utilisés entre deux IPs"""
        protocols = set()
        for packet in self.packets:
            if ((packet.get('src_ip') == ip1 and packet.get('dst_ip') == ip2) or
                (packet.get('src_ip') == ip2 and packet.get('dst_ip') == ip1)):
                if packet.get('protocol'):
                    protocols.add(packet['protocol'])
        return list(protocols)

# ============================================================================
# TEST DU MODULE
# ============================================================================

if __name__ == "__main__":
    print("=== Test du module Packet Analyzer ===\n")
    
    # Créer l'analyseur
    analyzer = PacketAnalyzer()
    
    # Lister les interfaces
    print("1. Interfaces réseau disponibles:")
    interfaces = analyzer.list_interfaces()
    for iface in interfaces:
        print(f"   • {iface['name']}: {iface['state']}")
        if iface['ip_addresses']:
            print(f"     IP: {', '.join(iface['ip_addresses'])}")
    
    print(f"\n2. Interface sélectionnée: {analyzer.interface}")
    
    # Test de capture rapide
    print("\n3. Test de capture (5 paquets, 5 secondes):")
    print("   Démarrage de la capture...")
    
    analyzer.start_capture(packet_count=5, timeout=5)
    
    # Attendre un peu
    time.sleep(3)
    
    analyzer.stop_capture()
    
    # Afficher les résultats
    status = analyzer.get_capture_status()
    print(f"   Statut: {'Capturing' if status['is_capturing'] else 'Stopped'}")
    print(f"   Paquets capturés: {len(analyzer.get_packets())}")
    
    # Afficher les statistiques
    stats = analyzer.get_statistics()
    print(f"\n4. Statistiques:")
    print(f"   Total paquets: {stats.get('total_packets', 0)}")
    print(f"   Total bytes: {stats.get('total_bytes', 0)}")
    
    if 'protocols' in stats:
        print(f"   Protocoles: {', '.join(stats['protocols'].keys())}")
    
    # Analyse des patterns
    print("\n5. Analyse des patterns:")
    analysis = analyzer.analyze_traffic_patterns()
    
    if analysis:
        if 'protocol_distribution' in analysis:
            print("   Distribution des protocoles:")
            for proto, count in analysis['protocol_distribution'].items():
                print(f"     {proto}: {count}")
    
    # Exporter en JSON
    json_file = analyzer.export_to_json()
    if json_file:
        print(f"\n6. Export JSON: {json_file}")
    
    print("\n✅ Test terminé avec succès!")