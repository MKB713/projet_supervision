#!/usr/bin/env python3
"""
Module de création de graphiques pour la supervision réseau
"""

import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import numpy as np
from datetime import datetime, timedelta
import json
import os
from typing import List, Dict, Optional, Tuple
import pandas as pd

class NetworkPlotter:
    """Classe pour créer des graphiques réseau"""
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialise le plotter
        
        Args:
            data_dir: Répertoire des données
        """
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
        # Configuration des styles
        plt.style.use('seaborn-v0_8-darkgrid')
        
        # Couleurs
        self.colors = {
            'success': '#2ecc71',  # Vert
            'warning': '#f39c12',  # Orange
            'error': '#e74c3c',    # Rouge
            'info': '#3498db',     # Bleu
            'gray': '#95a5a6',     # Gris
            'purple': '#9b59b6',   # Violet
        }
    
    def create_status_chart(self, devices: List[Dict]) -> Figure:
        """
        Crée un graphique de statut des équipements
        
        Args:
            devices: Liste des équipements
            
        Returns:
            Figure matplotlib
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if not devices:
            ax.text(0.5, 0.5, 'Aucune donnée disponible',
                   ha='center', va='center', fontsize=14)
            ax.set_title('Statut des Équipements', fontsize=16, fontweight='bold')
            return fig
        
        # Préparer les données
        names = [d.get('name', 'Inconnu') for d in devices]
        statuses = []
        
        for device in devices:
            status = device.get('status', '❓')
            if '✅' in status:
                statuses.append(1)  # En ligne
            elif '⚠️' in status:
                statuses.append(0.5)  # Avertissement
            else:
                statuses.append(0)  # Hors ligne
        
        # Créer le graphique à barres
        bars = ax.bar(names, statuses, color=self.colors['info'])
        
        # Colorer selon le statut
        for bar, status in zip(bars, statuses):
            if status == 1:
                bar.set_color(self.colors['success'])
            elif status == 0.5:
                bar.set_color(self.colors['warning'])
            else:
                bar.set_color(self.colors['error'])
        
        # Configuration des axes
        ax.set_ylim(0, 1.2)
        ax.set_ylabel('Statut', fontsize=12)
        ax.set_title('Statut des Équipements', fontsize=16, fontweight='bold', pad=20)
        
        # Rotation des labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
        
        # Ajouter les valeurs sur les barres
        for bar, status, device in zip(bars, statuses, devices):
            height = bar.get_height()
            status_text = device.get('status', '❓')
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.05,
                   status_text, ha='center', va='bottom', fontsize=10)
        
        # Légende
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor=self.colors['success'], label='En ligne'),
            Patch(facecolor=self.colors['warning'], label='Avertissement'),
            Patch(facecolor=self.colors['error'], label='Hors ligne')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        fig.tight_layout()
        return fig
    
    def create_uptime_chart(self, devices: List[Dict]) -> Figure:
        """
        Crée un graphique de temps de fonctionnement
        
        Args:
            devices: Liste des équipements
            
        Returns:
            Figure matplotlib
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if not devices:
            ax.text(0.5, 0.5, 'Aucune donnée disponible',
                   ha='center', va='center', fontsize=14)
            ax.set_title('Temps de Fonctionnement', fontsize=16, fontweight='bold')
            return fig
        
        # Extraire et parser l'uptime
        names = []
        uptime_days = []
        
        for device in devices:
            names.append(device.get('name', 'Inconnu'))
            uptime_str = device.get('uptime', '0')
            
            # Essayer de parser l'uptime SNMP
            try:
                # Format SNMP: Timeticks: (123456) 1 day, 2:34:56.78
                if 'Timeticks' in uptime_str:
                    # Extraire les ticks
                    ticks_str = uptime_str.split('(')[1].split(')')[0]
                    ticks = int(ticks_str)
                    days = ticks / (100 * 60 * 60 * 24)  # Convertir en jours
                    uptime_days.append(days)
                else:
                    uptime_days.append(0)
            except:
                uptime_days.append(0)
        
        # Créer le graphique
        bars = ax.barh(names, uptime_days, color=self.colors['purple'])
        
        # Configuration
        ax.set_xlabel('Jours de fonctionnement', fontsize=12)
        ax.set_title('Temps de Fonctionnement des Équipements', 
                    fontsize=16, fontweight='bold', pad=20)
        
        # Ajouter les valeurs
        for bar, days in zip(bars, uptime_days):
            width = bar.get_width()
            ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                   f'{days:.1f} jours', va='center', fontsize=10)
        
        fig.tight_layout()
        return fig
    
    def create_network_traffic_chart(self, traffic_data: Dict) -> Figure:
        """
        Crée un graphique de trafic réseau
        
        Args:
            traffic_data: Données de trafic
            
        Returns:
            Figure matplotlib
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Données exemple si pas de données réelles
        if not traffic_data:
            traffic_data = {
                'timestamps': [datetime.now() - timedelta(hours=i) for i in range(24)][::-1],
                'in_bytes': np.random.randint(1000, 10000, 24),
                'out_bytes': np.random.randint(1000, 8000, 24),
                'errors': np.random.randint(0, 10, 24)
            }
        
        timestamps = traffic_data.get('timestamps', [])
        in_bytes = traffic_data.get('in_bytes', [])
        out_bytes = traffic_data.get('out_bytes', [])
        errors = traffic_data.get('errors', [])
        
        # Graphique 1: Trafic entrant/sortant
        if timestamps and in_bytes and out_bytes:
            ax1.plot(timestamps, in_bytes, label='Trafic entrant', 
                    color=self.colors['success'], linewidth=2)
            ax1.plot(timestamps, out_bytes, label='Trafic sortant',
                    color=self.colors['info'], linewidth=2, linestyle='--')
        
        ax1.set_ylabel('Octets', fontsize=12)
        ax1.set_title('Trafic Réseau', fontsize=14, fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Format des dates sur l'axe x
        if timestamps:
            ax1.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M'))
        
        # Graphique 2: Erreurs
        if timestamps and errors:
            ax2.bar(timestamps, errors, color=self.colors['error'], alpha=0.7)
        
        ax2.set_xlabel('Heure', fontsize=12)
        ax2.set_ylabel('Erreurs', fontsize=12)
        ax2.set_title('Erreurs Réseau', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        
        # Format des dates
        if timestamps:
            ax2.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M'))
        
        fig.tight_layout()
        return fig
    
    def create_cpu_memory_chart(self, device_data: Dict) -> Figure:
        """
        Crée un graphique d'utilisation CPU/Mémoire
        
        Args:
            device_data: Données de l'équipement
            
        Returns:
            Figure matplotlib
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Données exemple
        cpu_data = device_data.get('cpu', {'usage': [20, 45, 30, 60, 40]})
        mem_data = device_data.get('memory', {'usage': [30, 35, 40, 45, 50]})
        
        # Graphique CPU
        ax1.pie([cpu_data['usage'][-1], 100 - cpu_data['usage'][-1]],
                labels=[f'Utilisé\n{cpu_data["usage"][-1]}%', 'Libre'],
                colors=[self.colors['warning'], self.colors['gray']],
                autopct='%1.1f%%', startangle=90)
        ax1.set_title('Utilisation CPU', fontsize=14, fontweight='bold')
        
        # Graphique Mémoire
        ax2.pie([mem_data['usage'][-1], 100 - mem_data['usage'][-1]],
                labels=[f'Utilisé\n{mem_data["usage"][-1]}%', 'Libre'],
                colors=[self.colors['info'], self.colors['gray']],
                autopct='%1.1f%%', startangle=90)
        ax2.set_title('Utilisation Mémoire', fontsize=14, fontweight='bold')
        
        fig.suptitle('Utilisation des Ressources', fontsize=16, fontweight='bold')
        fig.tight_layout()
        
        return fig
    
    def create_historical_chart(self, device_ip: str, metric: str = 'status') -> Figure:
        """
        Crée un graphique historique pour un équipement
        
        Args:
            device_ip: Adresse IP de l'équipement
            metric: Métrique à afficher (status, uptime, traffic)
            
        Returns:
            Figure matplotlib
        """
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Charger les données historiques
        data_file = os.path.join(self.data_dir, f"snmp_{device_ip.replace('.', '_')}.json")
        
        if os.path.exists(data_file):
            with open(data_file, 'r') as f:
                historical_data = json.load(f)
            
            # Préparer les données
            timestamps = []
            values = []
            
            for ts, data in list(historical_data.items())[-50:]:  # 50 derniers points
                try:
                    timestamp = datetime.fromisoformat(ts)
                    timestamps.append(timestamp)
                    
                    if metric == 'status':
                        # Simuler un statut (0=hors ligne, 1=en ligne)
                        values.append(1 if 'sysName' in data.get('system', {}) else 0)
                    elif metric == 'uptime':
                        uptime_str = data.get('system', {}).get('sysUpTime', '0')
                        if 'Timeticks' in uptime_str:
                            ticks = int(uptime_str.split('(')[1].split(')')[0])
                            days = ticks / (100 * 60 * 60 * 24)
                            values.append(days)
                    # Ajouter d'autres métriques ici
                    
                except Exception as e:
                    continue
            
            if timestamps and values:
                ax.plot(timestamps, values, marker='o', linestyle='-',
                       color=self.colors['info'], linewidth=2)
                
                # Remplissage sous la courbe
                ax.fill_between(timestamps, 0, values, alpha=0.3, color=self.colors['info'])
                
                # Configuration
                ax.set_xlabel('Heure', fontsize=12)
                ax.set_ylabel(metric.capitalize(), fontsize=12)
                ax.set_title(f'Historique {metric} - {device_ip}', 
                           fontsize=16, fontweight='bold', pad=20)
                ax.grid(True, alpha=0.3)
                
                # Format des dates
                ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M'))
        
        else:
            ax.text(0.5, 0.5, 'Aucune donnée historique disponible',
                   ha='center', va='center', fontsize=14)
            ax.set_title(f'Historique {metric} - {device_ip}', 
                        fontsize=16, fontweight='bold')
        
        fig.tight_layout()
        return fig
    
    def save_chart(self, fig: Figure, filename: str, dpi: int = 150):
        """
        Sauvegarde un graphique dans un fichier
        
        Args:
            fig: Figure à sauvegarder
            filename: Nom du fichier
            dpi: Résolution
        """
        output_dir = os.path.join(self.data_dir, 'charts')
        os.makedirs(output_dir, exist_ok=True)
        
        filepath = os.path.join(output_dir, filename)
        fig.savefig(filepath, dpi=dpi, bbox_inches='tight')
        print(f"Graphique sauvegardé: {filepath}")

class QtPlotter(FigureCanvas):
    """Plotter intégré à Qt"""
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        """
        Initialise le plotter Qt
        
        Args:
            parent: Widget parent
            width: Largeur
            height: Hauteur
            dpi: Résolution
        """
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.plotter = NetworkPlotter()
    
    def plot_status(self, devices: List[Dict]):
        """Afficher le graphique de statut"""
        self.fig.clear()
        
        fig = self.plotter.create_status_chart(devices)
        # Copier le contenu dans self.fig
        self.fig = fig
        self.draw()
    
    def plot_uptime(self, devices: List[Dict]):
        """Afficher le graphique d'uptime"""
        self.fig.clear()
        
        fig = self.plotter.create_uptime_chart(devices)
        self.fig = fig
        self.draw()
    
    def plot_traffic(self, traffic_data: Dict):
        """Afficher le graphique de trafic"""
        self.fig.clear()
        
        fig = self.plotter.create_network_traffic_chart(traffic_data)
        self.fig = fig
        self.draw()

# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    print("=== Test du module Plotter ===")
    
    # Créer un plotter
    plotter = NetworkPlotter()
    
    # Données exemple
    test_devices = [
        {'name': 'switch-01', 'status': '✅ Online', 'uptime': 'Timeticks: (1234567) 1 day, 10:17:36.78'},
        {'name': 'router-01', 'status': '✅ Online', 'uptime': 'Timeticks: (2345678) 2 days, 17:09:15.67'},
        {'name': 'nagios-server', 'status': '⚠️ Warning', 'uptime': 'Timeticks: (345678) 0 day, 09:36:15.78'},
        {'name': 'unknown-device', 'status': '❌ Offline', 'uptime': '0'}
    ]
    
    # Test 1: Graphique de statut