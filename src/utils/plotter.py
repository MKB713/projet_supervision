#!/usr/bin/env python3
"""
Module de création de graphiques pour la supervision réseau
"""

import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import os

class NetworkPlotter:
    """Générateur de graphiques pour la supervision réseau"""
    
    def __init__(self, style: str = 'seaborn'):
        """
        Initialise le plotter
        
        Args:
            style: Style matplotlib
        """
        self.style = style
        plt.style.use(style)
        
    def create_traffic_timeline(self, packets_data: List[Dict], 
                               timeframe: str = '1min') -> Figure:
        """
        Crée un graphique de timeline du trafic
        
        Args:
            packets_data: Liste des paquets
            timeframe: Période d'agrégation ('1s', '1min', '5min', '1h')
            
        Returns:
            Figure matplotlib
        """
        fig = Figure(figsize=(10, 6))
        ax = fig.add_subplot(111)
        
        if not packets_data:
            ax.text(0.5, 0.5, 'Aucune donnée disponible', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Convertir en DataFrame
        df = pd.DataFrame(packets_data)
        
        if 'timestamp' not in df.columns or df.empty:
            ax.text(0.5, 0.5, 'Données incomplètes', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Convertir les timestamps
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        
        # Agrégation selon le timeframe
        if timeframe == '1s':
            resample_str = '1S'
        elif timeframe == '1min':
            resample_str = '1T'
        elif timeframe == '5min':
            resample_str = '5T'
        else:  # '1h'
            resample_str = '1H'
        
        # Compter les paquets par période
        packets_count = df.resample(resample_str).size()
        
        # Compter les octets par période
        if 'length' in df.columns:
            bytes_count = df['length'].resample(resample_str).sum()
        
        # Créer le graphique
        ax.plot(packets_count.index, packets_count.values, 
               label='Paquets', color='#3498db', linewidth=2)
        
        if 'length' in df.columns:
            ax2 = ax.twinx()
            ax2.plot(bytes_count.index, bytes_count.values / 1024, 
                    label='Octets (KB)', color='#e74c3c', linewidth=2, alpha=0.7)
            ax2.set_ylabel('Octets (KB)', color='#e74c3c')
            ax2.tick_params(axis='y', labelcolor='#e74c3c')
        
        ax.set_xlabel('Temps')
        ax.set_ylabel('Paquets par période', color='#3498db')
        ax.tick_params(axis='y', labelcolor='#3498db')
        ax.set_title('Évolution du trafic réseau')
        ax.grid(True, alpha=0.3)
        ax.legend(loc='upper left')
        
        fig.tight_layout()
        return fig
    
    def create_protocol_distribution(self, packets_data: List[Dict]) -> Figure:
        """
        Crée un diagramme de distribution des protocoles
        
        Args:
            packets_data: Liste des paquets
            
        Returns:
            Figure matplotlib
        """
        fig = Figure(figsize=(8, 8))
        ax = fig.add_subplot(111)
        
        if not packets_data:
            ax.text(0.5, 0.5, 'Aucune donnée disponible', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        df = pd.DataFrame(packets_data)
        
        if 'protocol' not in df.columns or df.empty:
            ax.text(0.5, 0.5, 'Données incomplètes', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Compter les protocoles
        protocol_counts = df['protocol'].value_counts()
        
        # Couleurs
        colors = plt.cm.Set3(np.linspace(0, 1, len(protocol_counts)))
        
        # Créer le camembert
        wedges, texts, autotexts = ax.pie(
            protocol_counts.values,
            labels=protocol_counts.index,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors,
            wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )
        
        # Améliorer l'apparence
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        ax.set_title('Distribution des protocoles réseau', fontsize=14, fontweight='bold')
        
        # Légende
        ax.legend(wedges, protocol_counts.index,
                 title="Protocoles",
                 loc="center left",
                 bbox_to_anchor=(1, 0, 0.5, 1))
        
        return fig
    
    def create_top_talkers(self, packets_data: List[Dict], 
                          top_n: int = 10) -> Figure:
        """
        Crée un graphique des top talkers
        
        Args:
            packets_data: Liste des paquets
            top_n: Nombre de top talkers à afficher
            
        Returns:
            Figure matplotlib
        """
        fig = Figure(figsize=(10, 6))
        ax = fig.add_subplot(111)
        
        if not packets_data:
            ax.text(0.5, 0.5, 'Aucune donnée disponible', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        df = pd.DataFrame(packets_data)
        
        if 'src_ip' not in df.columns or df.empty:
            ax.text(0.5, 0.5, 'Données incomplètes', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Compter les paquets par source
        source_counts = df['src_ip'].value_counts().head(top_n)
        
        # Créer le graphique à barres
        bars = ax.barh(range(len(source_counts)), source_counts.values)
        
        # Configurer les axes
        ax.set_yticks(range(len(source_counts)))
        ax.set_yticklabels(source_counts.index)
        ax.invert_yaxis()  # Inverser pour avoir le plus grand en haut
        
        # Ajouter les valeurs sur les barres
        for i, (bar, count) in enumerate(zip(bars, source_counts.values)):
            ax.text(count + max(source_counts.values) * 0.01, 
                   bar.get_y() + bar.get_height()/2,
                   str(count), va='center')
        
        # Configuration
        ax.set_xlabel('Nombre de paquets')
        ax.set_title(f'Top {top_n} sources de trafic', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        fig.tight_layout()
        return fig
    
    def create_port_activity(self, packets_data: List[Dict], 
                           top_n: int = 15) -> Figure:
        """
        Crée un graphique d'activité des ports
        
        Args:
            packets_data: Liste des paquets
            top_n: Nombre de ports à afficher
            
        Returns:
            Figure matplotlib
        """
        fig = Figure(figsize=(12, 6))
        ax = fig.add_subplot(111)
        
        if not packets_data:
            ax.text(0.5, 0.5, 'Aucune donnée disponible', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        df = pd.DataFrame(packets_data)
        
        if 'dst_port' not in df.columns or df.empty:
            ax.text(0.5, 0.5, 'Données incomplètes', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Filtrer les ports nuls
        df = df[df['dst_port'].notna()]
        
        if df.empty:
            ax.text(0.5, 0.5, 'Aucun port de destination', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        # Compter les ports
        port_counts = df['dst_port'].value_counts().head(top_n)
        
        # Associer les services aux ports connus
        port_services = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS',
            25: 'SMTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP',
            162: 'SNMP Trap', 67: 'DHCP Server', 68: 'DHCP Client',
            123: 'NTP', 389: 'LDAP', 636: 'LDAPS', 3306: 'MySQL',
            5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis'
        }
        
        # Créer les labels
        labels = []
        for port in port_counts.index:
            if port in port_services:
                labels.append(f"{port} ({port_services[port]})")
            else:
                labels.append(str(port))
        
        # Créer le graphique
        colors = plt.cm.viridis(np.linspace(0, 1, len(port_counts)))
        bars = ax.bar(range(len(port_counts)), port_counts.values, color=colors)
        
        # Configuration
        ax.set_xticks(range(len(port_counts)))
        ax.set_xticklabels(labels, rotation=45, ha='right')
        ax.set_ylabel('Nombre de paquets')
        ax.set_title(f'Top {top_n} ports de destination', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')
        
        # Ajouter les valeurs
        for bar, count in zip(bars, port_counts.values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   str(count), ha='center', va='bottom')
        
        fig.tight_layout()
        return fig
    
    def create_alert_timeline(self, alerts_data: List[Dict]) -> Figure:
        """
        Crée une timeline des alertes
        
        Args:
            alerts_data: Liste des alertes
            
        Returns:
            Figure matplotlib
        """
        fig = Figure(figsize=(10, 4))
        ax = fig.add_subplot(111)
        
        if not alerts_data:
            ax.text(0.5, 0.5, 'Aucune alerte', 
                   ha='center', va='center', transform=ax.transAxes)
            return fig
        
        df = pd.DataFrame(alerts_data)
        
        if 'timestamp' not in df.columns or df.empty:
            ax.text(0.5, 0.5, 'Données incomplètes', 
                   ha='center', va