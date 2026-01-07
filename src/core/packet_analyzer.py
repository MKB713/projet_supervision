#!/usr/bin/env python3
"""
Module d'analyse de paquets réseau
"""

try:
    import pyshark
    PTSHARK_AVAILABLE = True
except ImportError:
    PTSHARK_AVAILABLE = False
    print("⚠️  pyshark non disponible - capture désactivée")

import pandas as pd
from datetime import datetime
import json
from collections import defaultdict
from typing import List, Dict, Optional

class PacketAnalyzer:
    """Analyseur de paquets réseau"""
    
    def __init__(self, interface: str = 'lo'):
        """
        Initialise l'analyseur de paquets
        
        Args:
            interface: Interface réseau à écouter
        """
        self.interface = interface
        self.capture = None
        self.is_capturing = False
        self.packets = []
        self.statistics = defaultdict(int)
        
    def start_capture(self, packet_count: int = 100, timeout: int = 30) -> bool:
        """
        Démarre une capture de paquets
        
        Args:
            packet_count: Nombre maximum de paquets
            timeout: Timeout en secondes
            
        Returns:
            bool: True si la capture démarre
        """
        if not PTSHARK_AVAILABLE:
            print("❌ pyshark non installé. Installez-le: pip install pyshark")
            return False
            
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=''  # Tous les paquets
            )
            
            self.is_capturing = True
            self.packets = []
            self.statistics.clear()
            
            print(f"✅ Capture démarrée sur {self.interface}")
            print(f"   Max paquets: {packet_count}, Timeout: {timeout}s")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur démarrage capture: {e}")
            return False
    
    def stop_capture(self):
        """Arrête la capture"""
        self.is_capturing = False
        if self.capture:
            self.capture.close()
        print("⏹️  Capture arrêtée")
    
    def get_packets(self) -> List[Dict]:
        """Retourne les paquets capturés"""
        return self.packets
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques"""
        return dict(self.statistics)
    
    def test_simple_capture(self) -> List[Dict]:
        """
        Capture simple pour tests
        
        Returns:
            Liste de paquets simulés
        """
        print("🧪 Capture de test (simulée)...")
        
        # Paquets simulés pour tests
        simulated_packets = [
            {
                'timestamp': datetime.now().isoformat(),
                'src_ip': '10.158.68.115',
                'dst_ip': '10.158.68.200',
                'protocol': 'TCP',
                'src_port': '54321',
                'dst_port': '80',
                'length': 1500
            },
            {
                'timestamp': datetime.now().isoformat(),
                'src_ip': '10.158.68.200',
                'dst_ip': '10.158.68.115',
                'protocol': 'TCP',
                'src_port': '80',
                'dst_port': '54321',
                'length': 1200
            },
            {
                'timestamp': datetime.now().isoformat(),
                'src_ip': '10.158.68.201',
                'dst_ip': '10.158.68.202',
                'protocol': 'ICMP',
                'length': 84
            }
        ]
        
        self.packets = simulated_packets
        
        # Statistiques simulées
        self.statistics = {
            'total_packets': 3,
            'total_bytes': 2784,
            'protocol_TCP': 2,
            'protocol_ICMP': 1
        }
        
        return simulated_packets

if __name__ == "__main__":
    print("=== Test Packet Analyzer ===")
    analyzer = PacketAnalyzer()
    
    # Test simple
    packets = analyzer.test_simple_capture()
    print(f"\n📦 {len(packets)} paquets simulés:")
    
    for i, packet in enumerate(packets, 1):
        print(f"\nPaquet {i}:")
        for key, value in packet.items():
            print(f"  {key}: {value}")
    
    print(f"\n📊 Statistiques: {analyzer.get_statistics()}")