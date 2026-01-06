#!/usr/bin/env python3
"""
Interface graphique principale - Plateforme de Supervision Réseau
"""

import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

# PyQt5 imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QGroupBox, QGridLayout, QLineEdit, QTextEdit, QMessageBox,
    QComboBox, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QSplitter, QFormLayout, QHeaderView, QMenuBar, QMenu, QAction,
    QStatusBar, QToolBar, QFileDialog, QInputDialog
)
from PyQt5.QtCore import (
    Qt, QTimer, QDateTime, QSize, pyqtSignal, QThread
)
from PyQt5.QtGui import (
    QIcon, QFont, QPalette, QColor, QBrush, QPixmap
)

# Imports matplotlib pour graphiques
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

# Nos modules
from core.snmp_manager import SNMPManager
from core.nagios_client import NagiosClient
from core.packet_analyzer import PacketAnalyzer

class DashboardTab(QWidget):
    """Onglet Tableau de Bord principal"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.refresh_data()
        
    def init_ui(self):
        # Layout principal
        main_layout = QVBoxLayout()
        
        # Titre
        title = QLabel("🏠 Tableau de Bord - Supervision Réseau")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        main_layout.addWidget(title)
        
        # Grille de statistiques
        stats_grid = QGridLayout()
        
        # Carte 1: Statut Global
        card1 = self.create_card("🌐 Statut Global", """
        <div style='text-align: center;'>
            <h3 style='color: #27ae60;'>● Système Stable</h3>
            <p>Tous les services fonctionnent normalement</p>
            <p><b>Dernière vérification:</b> Chargement...</p>
        </div>
        """)
        stats_grid.addWidget(card1, 0, 0)
        
        # Carte 2: Équipements
        card2 = self.create_card("🖥️ Équipements", """
        <div style='text-align: center;'>
            <h2 style='color: #3498db;'>3/3</h2>
            <p>Équipements en ligne</p>
            <p><small>Nagios: ✅ | Switch: ✅ | Router: ✅</small></p>
        </div>
        """)
        stats_grid.addWidget(card2, 0, 1)
        
        # Carte 3: Alertes
        card3 = self.create_card("⚠️ Alertes", """
        <div style='text-align: center;'>
            <h2 style='color: #e74c3c;'>0</h2>
            <p>Alertes actives</p>
            <p><small>Dernière alerte: Aucune</small></p>
        </div>
        """)
        stats_grid.addWidget(card3, 1, 0)
        
        # Carte 4: Performance
        card4 = self.create_card("📊 Performance", """
        <div style='text-align: center;'>
            <h3 style='color: #9b59b6;'>● Optimale</h3>
            <p>Latence réseau: < 10ms</p>
            <p>Disponibilité: 99.9%</p>
        </div>
        """)
        stats_grid.addWidget(card4, 1, 1)
        
        stats_widget = QWidget()
        stats_widget.setLayout(stats_grid)
        main_layout.addWidget(stats_widget)
        
        # Graphiques
        charts_layout = QHBoxLayout()
        
        # Graphique 1: Utilisation CPU
        self.cpu_chart = self.create_chart("Utilisation CPU", ["Nagios", "Switch", "Router"])
        charts_layout.addWidget(self.cpu_chart)
        
        # Graphique 2: Trafic réseau
        self.traffic_chart = self.create_chart("Trafic Réseau (Mbps)", ["Entrant", "Sortant"])
        charts_layout.addWidget(self.traffic_chart)
        
        charts_widget = QWidget()
        charts_widget.setLayout(charts_layout)
        main_layout.addWidget(charts_widget)
        
        # Logs en temps réel
        logs_group = QGroupBox("📝 Logs en Temps Réel")
        logs_layout = QVBoxLayout()
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setMaximumHeight(150)
        self.logs_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Courier New', monospace;
                padding: 5px;
            }
        """)
        logs_layout.addWidget(self.logs_text)
        logs_group.setLayout(logs_layout)
        main_layout.addWidget(logs_group)
        
        self.setLayout(main_layout)
        
        # Timer pour les mises à jour
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_data)
        self.update_timer.start(5000)  # Toutes les 5 secondes
        
    def create_card(self, title: str, content: str) -> QGroupBox:
        """Crée une carte de statistique"""
        card = QGroupBox(title)
        card.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #34495e;
            }
        """)
        
        layout = QVBoxLayout()
        label = QLabel(content)
        label.setAlignment(Qt.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)
        card.setLayout(layout)
        
        return card
        
    def create_chart(self, title: str, labels: List[str]) -> QWidget:
        """Crée un widget avec un graphique"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Titre
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(title_label)
        
        # Canvas matplotlib
        self.figure = Figure(figsize=(4, 3), dpi=80)
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Données exemple
        self.update_chart(labels)
        
        widget.setLayout(layout)
        return widget
        
    def update_chart(self, labels: List[str]):
        """Met à jour le graphique"""
        ax = self.figure.add_subplot(111)
        ax.clear()
        
        # Données exemple
        data = [25, 40, 35] if len(labels) == 3 else [45, 55]
        colors = ['#3498db', '#2ecc71', '#e74c3c'] if len(labels) == 3 else ['#3498db', '#9b59b6']
        
        bars = ax.bar(labels, data, color=colors)
        ax.set_ylim(0, 100)
        ax.set_ylabel('Pourcentage (%)')
        ax.grid(True, alpha=0.3)
        
        # Ajouter les valeurs sur les barres
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                   f'{int(height)}%', ha='center', va='bottom')
        
        self.canvas.draw()
        
    def refresh_data(self):
        """Rafraîchit les données du dashboard"""
        current_time = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.log(f"[{current_time}] Mise à jour des données...")
        
        # Ici, vous ajouterez le code pour récupérer les vraies données
        # depuis SNMP et Nagios

    def log(self, message: str):
        """Ajoute un message aux logs"""
        current_log = self.logs_text.toPlainText()
        new_log = f"{message}\n{current_log}"
        if len(new_log.split('\n')) > 20:
            new_log = '\n'.join(new_log.split('\n')[:20])
        self.logs_text.setText(new_log)

class SNMPTab(QWidget):
    """Onglet Supervision SNMP"""
    
    def __init__(self):
        super().__init__()
        self.snmp_manager = SNMPManager(community='supervision')
        self.init_ui()
        self.refresh_devices()
        
    def init_ui(self):
        # Layout principal avec splitter
        main_layout = QVBoxLayout()
        
        # Barre d'outils
        toolbar = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Adresse IP (ex: 10.158.68.201)")
        self.ip_input.setText("10.158.68.201")
        self.ip_input.setFixedWidth(200)
        
        self.community_input = QLineEdit()
        self.community_input.setPlaceholderText("Communauté SNMP")
        self.community_input.setText("supervision")
        self.community_input.setFixedWidth(150)
        
        scan_btn = QPushButton("🔍 Scanner")
        scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        scan_btn.clicked.connect(self.scan_device)
        
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_devices)
        
        discover_btn = QPushButton("🌐 Découvrir")
        discover_btn.clicked.connect(self.discover_devices)
        
        toolbar.addWidget(QLabel("IP:"))
        toolbar.addWidget(self.ip_input)
        toolbar.addWidget(QLabel("Communauté:"))
        toolbar.addWidget(self.community_input)
        toolbar.addWidget(scan_btn)
        toolbar.addWidget(refresh_btn)
        toolbar.addWidget(discover_btn)
        toolbar.addStretch()
        
        main_layout.addLayout(toolbar)
        
        # Splitter pour deux panneaux
        splitter = QSplitter(Qt.Horizontal)
        
        # Panneau gauche : Liste des équipements
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        
        devices_label = QLabel("📡 Équipements Découverts")
        devices_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50;")
        left_layout.addWidget(devices_label)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            "IP", "Nom", "Description", "Statut", "Uptime", "Actions"
        ])
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #bdc3c7;
                selection-background-color: #3498db;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 5px;
                border: 1px solid #2c3e50;
            }
        """)
        
        # Connecter le clic sur une ligne
        self.device_table.cellClicked.connect(self.on_device_selected)
        
        left_layout.addWidget(self.device_table)
        left_panel.setLayout(left_layout)
        
        # Panneau droit : Détails de l'équipement
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        
        details_label = QLabel("📋 Informations Détaillées")
        details_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50;")
        right_layout.addWidget(details_label)
        
        # Formulaire de détails
        form_group = QGroupBox("Système")
        form_layout = QFormLayout()
        
        self.sysname_label = QLabel("-")
        self.sysdesc_label = QLabel("-")
        self.sysuptime_label = QLabel("-")
        self.syslocation_label = QLabel("-")
        self.syscontact_label = QLabel("-")
        
        form_layout.addRow("Nom:", self.sysname_label)
        form_layout.addRow("Description:", self.sysdesc_label)
        form_layout.addRow("Uptime:", self.sysuptime_label)
        form_layout.addRow("Localisation:", self.syslocation_label)
        form_layout.addRow("Contact:", self.syscontact_label)
        
        form_group.setLayout(form_layout)
        right_layout.addWidget(form_group)
        
        # Statistiques interface
        stats_group = QGroupBox("📶 Statistiques Interface")
        stats_layout = QFormLayout()
        
        self.if_status_label = QLabel("-")
        self.if_in_octets_label = QLabel("-")
        self.if_out_octets_label = QLabel("-")
        self.if_in_errors_label = QLabel("-")
        self.if_out_errors_label = QLabel("-")
        
        stats_layout.addRow("État:", self.if_status_label)
        stats_layout.addRow("Octets entrants:", self.if_in_octets_label)
        stats_layout.addRow("Octets sortants:", self.if_out_octets_label)
        stats_layout.addRow("Erreurs entrantes:", self.if_in_errors_label)
        stats_layout.addRow("Erreurs sortantes:", self.if_out_errors_label)
        
        stats_group.setLayout(stats_layout)
        right_layout.addWidget(stats_group)
        
        # Boutons d'action
        action_layout = QHBoxLayout()
        
        monitor_btn = QPushButton("📊 Surveiller")
        monitor_btn.clicked.connect(self.start_monitoring)
        
        ping_btn = QPushButton("📡 Tester Ping")
        ping_btn.clicked.connect(self.test_ping)
        
        action_layout.addWidget(monitor_btn)
        action_layout.addWidget(ping_btn)
        action_layout.addStretch()
        
        right_layout.addLayout(action_layout)
        right_layout.addStretch()
        
        right_panel.setLayout(right_layout)
        
        # Ajouter les panneaux au splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 300])
        
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        
    def refresh_devices(self):
        """Rafraîchit la liste des équipements"""
        # Données exemple
        devices = [
            ["10.158.68.200", "nagios-server", "Ubuntu Server 24.04", "✅ En ligne", "5j 3h", "🔄"],
            ["10.158.68.201", "switch-01", "Switch Simulé", "✅ En ligne", "2j 8h", "🔄"],
            ["10.158.68.202", "router-01", "Routeur Simulé", "✅ En ligne", "1j 12h", "🔄"]
        ]
        
        self.device_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            for col, value in enumerate(device):
                item = QTableWidgetItem(value)
                if col == 3:  # Statut
                    if "✅" in value:
                        item.setForeground(QBrush(QColor("#27ae60")))
                    elif "⚠️" in value:
                        item.setForeground(QBrush(QColor("#f39c12")))
                    elif "❌" in value:
                        item.setForeground(QBrush(QColor("#e74c3c")))
                self.device_table.setItem(row, col, item)
                
    def discover_devices(self):
        """Découvre les équipements SNMP"""
        QMessageBox.information(self, "Découverte", 
            "Découverte d'équipements en cours...\n(Cette fonctionnalité sera implémentée)")
        
    def scan_device(self):
        """Scanne un équipement spécifique"""
        ip = self.ip_input.text()
        community = self.community_input.text()
        
        if not ip:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP")
            return
            
        try:
            QMessageBox.information(self, "Scan SNMP", 
                f"Scan de {ip} avec communauté '{community}'...")
            
            # Ici, vous ajouterez le code pour scanner réellement l'équipement
            # info = self.snmp_manager.get_system_info(ip)
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors du scan: {str(e)}")
            
    def on_device_selected(self, row, column):
        """Quand un équipement est sélectionné"""
        ip = self.device_table.item(row, 0).text()
        self.update_device_details(ip)
        
    def update_device_details(self, ip: str):
        """Met à jour les détails de l'équipement"""
        # Données exemple
        details = {
            'sysname': 'switch-01',
            'sysdesc': 'Ubuntu 24.04 LTS - Switch Simulé',
            'sysuptime': '2 jours 8 heures 15 minutes',
            'syslocation': 'Salle serveur virtuelle',
            'syscontact': 'admin@lab.local'
        }
        
        self.sysname_label.setText(details['sysname'])
        self.sysdesc_label.setText(details['sysdesc'])
        self.sysuptime_label.setText(details['sysuptime'])
        self.syslocation_label.setText(details['syslocation'])
        self.syscontact_label.setText(details['syscontact'])
        
        # Statistiques exemple
        self.if_status_label.setText("✅ UP (1000 Mbps)")
        self.if_in_octets_label.setText("1.2 GB")
        self.if_out_octets_label.setText("850 MB")
        self.if_in_errors_label.setText("0")
        self.if_out_errors_label.setText("0")
        
    def start_monitoring(self):
        """Démarre la surveillance de l'équipement"""
        QMessageBox.information(self, "Surveillance", 
            "Démarrage de la surveillance...")
            
    def test_ping(self):
        """Teste la connectivité Ping"""
        QMessageBox.information(self, "Test Ping", 
            "Test Ping en cours...")

class NagiosTab(QWidget):
    """Onglet Interface Nagios"""
    
    def __init__(self):
        super().__init__()
        self.nagios_client = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # En-tête
        header = QLabel("⚠️ Interface Nagios")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #e74c3c;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Statut de connexion
        status_group = QGroupBox("Connexion")
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("🔍 Vérification...")
        self.status_label.setStyleSheet("font-weight: bold;")
        
        test_btn = QPushButton("Tester la connexion")
        test_btn.clicked.connect(self.test_connection)
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(test_btn)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Onglets pour les données Nagios
        nagios_tabs = QTabWidget()
        
        # Onglet Hôtes
        hosts_tab = QWidget()
        hosts_layout = QVBoxLayout()
        
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderLabels(["Hôte", "Adresse", "Statut", "Dernière vérification"])
        self.hosts_tree.setStyleSheet("""
            QTreeWidget {
                font-family: 'Courier New', monospace;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        
        hosts_layout.addWidget(self.hosts_tree)
        hosts_tab.setLayout(hosts_layout)
        
        # Onglet Services
        services_tab = QWidget()
        services_layout = QVBoxLayout()
        
        self.services_table = QTableWidget()
        self.services_table.setColumnCount(5)
        self.services_table.setHorizontalHeaderLabels([
            "Hôte", "Service", "Statut", "Sortie", "Dernière vérification"
        ])
        services_layout.addWidget(self.services_table)
        services_tab.setLayout(services_layout)
        
        # Onglet Alertes
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout()
        
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)
        alerts_layout.addWidget(self.alerts_text)
        alerts_tab.setLayout(alerts_layout)
        
        nagios_tabs.addTab(hosts_tab, "🏠 Hôtes")
        nagios_tabs.addTab(services_tab, "🔧 Services")
        nagios_tabs.addTab(alerts_tab, "⚠️ Alertes")
        
        layout.addWidget(nagios_tabs)
        
        # Boutons d'action
        action_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_data)
        
        acknowledge_btn = QPushButton("✓ Acquitter")
        acknowledge_btn.clicked.connect(self.acknowledge_alert)
        
        action_layout.addWidget(refresh_btn)
        action_layout.addWidget(acknowledge_btn)
        action_layout.addStretch()
        
        layout.addLayout(action_layout)
        self.setLayout(layout)
        
        # Tester la connexion au démarrage
        self.test_connection()
        
    def test_connection(self):
        """Teste la connexion à Nagios"""
        if self.nagios_client.test_connection():
            self.status_label.setText("✅ Connecté à Nagios")
            self.status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
            self.refresh_data()
        else:
            self.status_label.setText("❌ Non connecté")
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def refresh_data(self):
        """Rafraîchit les données Nagios"""
        # Exemple de données
        hosts_data = [
            ["switch-01", "10.158.68.201", "✅ UP", "2024-01-07 14:30:00"],
            ["router-01", "10.158.68.202", "✅ UP", "2024-01-07 14:29:45"],
            ["nagios-server", "10.158.68.200", "✅ UP", "2024-01-07 14:29:30"]
        ]
        
        self.hosts_tree.clear()
        for host in hosts_data:
            item = QTreeWidgetItem(host)
            if host[2] == "✅ UP":
                item.setForeground(2, QBrush(QColor("#27ae60")))
            self.hosts_tree.addTopLevelItem(item)
            
        # Données services
        services_data = [
            ["switch-01", "PING", "✅ OK", "RTT: 2ms", "14:30:00"],
            ["switch-01", "SNMP", "✅ OK", "Uptime: 2d", "14:30:00"],
            ["router-01", "PING", "✅ OK", "RTT: 3ms", "14:29:45"]
        ]
        
        self.services_table.setRowCount(len(services_data))
        for row, service in enumerate(services_data):
            for col, value in enumerate(service):
                item = QTableWidgetItem(value)
                if col == 2 and "✅" in value:
                    item.setForeground(QBrush(QColor("#27ae60")))
                self.services_table.setItem(row, col, item)
                
        # Alertes
        self.alerts_text.setText("✅ Aucune alerte récente")
        
    def acknowledge_alert(self):
        """Acquitte une alerte"""
        QMessageBox.information(self, "Acquittement", 
            "Fonction d'acquittement d'alerte")

class PacketAnalyzerTab(QWidget):
    """Onglet Analyseur de Paquets"""
    
    def __init__(self):
        super().__init__()
        self.packet_analyzer = PacketAnalyzer(interface='lo')
        self.is_capturing = False
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # En-tête
        header = QLabel("📊 Analyseur de Paquets")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #9b59b6;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Contrôles de capture
        controls_group = QGroupBox("Contrôles de Capture")
        controls_layout = QGridLayout()
        
        # Interface réseau
        controls_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["lo", "eth0", "wlan0"])
        controls_layout.addWidget(self.interface_combo, 0, 1)
        
        # Filtre
        controls_layout.addWidget(QLabel("Filtre:"), 1, 0)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("ex: port 80 or icmp")
        controls_layout.addWidget(self.filter_input, 1, 1)
        
        # Nombre de paquets
        controls_layout.addWidget(QLabel("Paquets:"), 2, 0)
        self.packet_count = QLineEdit("100")
        self.packet_count.setFixedWidth(80)
        controls_layout.addWidget(self.packet_count, 2, 1)
        
        # Boutons
        self.start_btn = QPushButton("▶️ Démarrer")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
        """)
        
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
        """)
        
        save_btn = QPushButton("💾 Sauvegarder")
        save_btn.clicked.connect(self.save_capture)
        
        controls_layout.addWidget(self.start_btn, 0, 2)
        controls_layout.addWidget(self.stop_btn, 1, 2)
        controls_layout.addWidget(save_btn, 2, 2)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Statistiques en temps réel
        stats_group = QGroupBox("📈 Statistiques en Temps Réel")
        stats_layout = QGridLayout()
        
        stats_labels = [
            ("Paquets capturés:", "0"),
            ("Débit:", "0 Mbps"),
            ("TCP:", "0%"),
            ("UDP:", "0%"),
            ("ICMP:", "0%"),
            ("HTTP:", "0%")
        ]
        
        for i, (label, value) in enumerate(stats_labels):
            stats_layout.addWidget(QLabel(label), i//3, (i%3)*2)
            value_label = QLabel(value)
            value_label.setStyleSheet("font-weight: bold;")
            stats_layout.addWidget(value_label, i//3, (i%3)*2+1)
            
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Liste des paquets
        packets_group = QGroupBox("📦 Paquets Capturés")
        packets_layout = QVBoxLayout()
        
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(6)
        self.packets_table.setHorizontalHeaderLabels([
            "No.", "Heure", "Source", "Destination", "Protocole", "Taille"
        ])
        self.packets_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        packets_layout.addWidget(self.packets_table)
        packets_group.setLayout(packets_layout)
        layout.addWidget(packets_group)
        
        self.setLayout(layout)
        
    def start_capture(self):
        """Démarre la capture réseau"""
        self.is_capturing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # Exemple de paquets
        packets = [
            ["1", "14:30:01.123", "10.158.68.115:54321", "10.158.68.200:80", "TCP", "1500"],
            ["2", "14:30:01.125", "10.158.68.200:80", "10.158.68.115:54321", "TCP", "1452"],
            ["3", "14:30:01.230", "10.158.68.201:161", "10.158.68.200:48723", "UDP", "484"],
            ["4", "14:30:01.450", "10.158.68.115", "8.8.8.8", "ICMP", "84"],
        ]
        
        self.packets_table.setRowCount(len(packets))
        for row, packet in enumerate(packets):
            for col, value in enumerate(packet):
                item = QTableWidgetItem(value)
                self.packets_table.setItem(row, col, item)
                
    def stop_capture(self):
        """Arrête la capture réseau"""
        self.is_capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
    def save_capture(self):
        """Sauvegarde la capture"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Sauvegarder la capture", "", "PCAP Files (*.pcap);;All Files (*)"
        )
        if filename:
            QMessageBox.information(self, "Sauvegarde", 
                f"Capture sauvegardée dans:\n{filename}")

class MainWindow(QMainWindow):
    """Fenêtre principale de l'application"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        # Configuration de la fenêtre
        self.setWindowTitle("🌐 Plateforme de Supervision Réseau")
        self.setGeometry(100, 100, 1400, 800)
        
        # Style de l'application
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
            }
            QTabWidget::pane {
                border: 1px solid #bdc3c7;
                background-color: white;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #34495e;
                color: white;
                padding: 10px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #2980b9;
            }
        """)
        
        # Barre de menu
        self.create_menu_bar()
        
        # Barre d'outils
        self.create_tool_bar()
        
        # Widget central avec onglets
        self.tab_widget = QTabWidget()
        
        # Créer les onglets
        self.dashboard_tab = DashboardTab()
        self.snmp_tab = SNMPTab()
        self.nagios_tab = NagiosTab()
        self.analyzer_tab = PacketAnalyzerTab()
        
        self.tab_widget.addTab(self.dashboard_tab, "🏠 Tableau de Bord")
        self.tab_widget.addTab(self.snmp_tab, "📡 SNMP")
        self.tab_widget.addTab(self.nagios_tab, "⚠️ Nagios")
        self.tab_widget.addTab(self.analyzer_tab, "📊 Analyse Paquets")
        
        self.setCentralWidget(self.tab_widget)
        
        # Barre de statut
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Prêt - Connecté au réseau 10.158.68.0/21")
        
        # Timer pour les mises à jour
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(10000)  # Toutes les 10 secondes
        
    def create_menu_bar(self):
        """Crée la barre de menu"""
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu('📁 Fichier')
        
        new_action = QAction('Nouveau', self)
        file_menu.addAction(new_action)
        
        save_action = QAction('Sauvegarder', self)
        save_action.setShortcut('Ctrl+S')
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Quitter', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction