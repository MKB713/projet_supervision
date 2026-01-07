#!/usr/bin/env python3
"""
Interface graphique principale - Supervision Réseau
"""

import sys
import os
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import threading
import time

# Import nos modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.snmp_manager import SNMPManager
from core.nagios_client import NagiosClient

class DashboardWidget(QWidget):
    """Widget du tableau de bord"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.snmp_manager = SNMPManager(community='supervision')
        self.init_ui()
        self.start_monitoring()
    
    def init_ui(self):
        """Initialiser l'interface"""
        main_layout = QVBoxLayout()
        
        # Titre
        title = QLabel("📊 TABLEAU DE BORD - SUPERVISION RÉSEAU")
        title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #2c3e50;
            padding: 15px;
            background-color: #ecf0f1;
            border-radius: 10px;
        """)
        main_layout.addWidget(title)
        
        # Cartes d'état
        cards_layout = QGridLayout()
        
        # Carte 1: Statut global
        self.card_global = self.create_card("🌐 État Global", "Tous les systèmes fonctionnent")
        self.card_global.setStyleSheet("background-color: #d5f4e6;")
        cards_layout.addWidget(self.card_global, 0, 0)
        
        # Carte 2: Équipements
        self.card_devices = self.create_card("🖥️ Équipements", "En ligne: 0/0")
        cards_layout.addWidget(self.card_devices, 0, 1)
        
        # Carte 3: Alertes
        self.card_alerts = self.create_card("⚠️ Alertes", "Actives: 0")
        self.card_alerts.setStyleSheet("background-color: #f8d7da;")
        cards_layout.addWidget(self.card_alerts, 1, 0)
        
        # Carte 4: Performance
        self.card_perf = self.create_card("📈 Performance", "Charge réseau: N/A")
        cards_layout.addWidget(self.card_perf, 1, 1)
        
        main_layout.addLayout(cards_layout)
        
        # Graphique
        self.figure = Figure(figsize=(8, 4))
        self.canvas = FigureCanvas(self.figure)
        main_layout.addWidget(self.canvas)
        
        # Boutons d'action
        btn_layout = QHBoxLayout()
        
        btn_scan = QPushButton("🔍 Scanner le réseau")
        btn_scan.clicked.connect(self.scan_network)
        btn_scan.setStyleSheet(self.get_button_style())
        
        btn_refresh = QPushButton("🔄 Actualiser")
        btn_refresh.clicked.connect(self.refresh_data)
        btn_refresh.setStyleSheet(self.get_button_style())
        
        btn_settings = QPushButton("⚙️ Paramètres")
        btn_settings.clicked.connect(self.open_settings)
        btn_settings.setStyleSheet(self.get_button_style())
        
        btn_layout.addWidget(btn_scan)
        btn_layout.addWidget(btn_refresh)
        btn_layout.addWidget(btn_settings)
        btn_layout.addStretch()
        
        main_layout.addLayout(btn_layout)
        
        self.setLayout(main_layout)
    
    def create_card(self, title, content):
        """Créer une carte d'information"""
        card = QGroupBox(title)
        card.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        label = QLabel(content)
        label.setStyleSheet("font-size: 16px; padding: 10px;")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        card.setLayout(layout)
        
        return card
    
    def get_button_style(self):
        """Style pour les boutons"""
        return """
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c6ea4;
            }
        """
    
    def start_monitoring(self):
        """Démarrer la surveillance en arrière-plan"""
        self.monitor_thread = threading.Thread(target=self.update_monitoring, daemon=True)
        self.monitor_thread.start()
    
    def update_monitoring(self):
        """Mettre à jour les données périodiquement"""
        while True:
            try:
                self.refresh_data()
                time.sleep(30)  # Actualiser toutes les 30 secondes
            except:
                time.sleep(5)
    
    def scan_network(self):
        """Scanner le réseau"""
        QMessageBox.information(self, "Scan réseau", 
                               "Démarrage du scan réseau...")
        
        # En arrière-plan
        thread = threading.Thread(target=self.perform_scan)
        thread.start()
    
    def perform_scan(self):
        """Effectuer le scan en arrière-plan"""
        devices = self.snmp_manager.discover_devices()
        
        # Mettre à jour l'interface dans le thread principal
        self.parent().parent().statusBar().showMessage(
            f"Scan terminé: {len(devices)} équipement(s) trouvé(s)", 5000)
        
        # Mettre à jour la carte
        text = f"En ligne: {len(devices)}/3"
        self.update_card_text(self.card_devices, text)
    
    def refresh_data(self):
        """Actualiser toutes les données"""
        try:
            # Récupérer les équipements
            devices = self.snmp_manager.discover_devices()
            online_count = len([d for d in devices if '✅' in d.get('status', '')])
            
            # Mettre à jour les cartes
            self.update_card_text(self.card_devices, f"En ligne: {online_count}/{len(devices)}")
            
            # Mettre à jour le statut global
            if online_count == 3:
                status = "✅ Tous les systèmes fonctionnent"
                color = "#d5f4e6"
            elif online_count >= 1:
                status = f"⚠️ {online_count}/3 systèmes en ligne"
                color = "#fff3cd"
            else:
                status = "❌ Aucun système en ligne"
                color = "#f8d7da"
            
            self.update_card_text(self.card_global, status)
            self.card_global.setStyleSheet(f"background-color: {color};")
            
            # Mettre à jour le graphique
            self.update_chart(devices)
            
        except Exception as e:
            print(f"Erreur refresh: {e}")
    
    def update_card_text(self, card, text):
        """Mettre à jour le texte d'une carte"""
        for i in range(card.layout().count()):
            widget = card.layout().itemAt(i).widget()
            if isinstance(widget, QLabel):
                widget.setText(text)
                break
    
    def update_chart(self, devices):
        """Mettre à jour le graphique"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        if devices:
            # Données exemple (dans la réalité, on récupérerait les vraies données)
            names = [d['name'] for d in devices]
            status = [1 if '✅' in d.get('status', '') else 0 for d in devices]
            
            colors = ['#2ecc71' if s == 1 else '#e74c3c' for s in status]
            
            bars = ax.bar(names, status, color=colors)
            ax.set_ylim(0, 1.2)
            ax.set_ylabel('Statut (1=OK, 0=KO)')
            ax.set_title('Statut des Équipements')
            ax.set_xticklabels(names, rotation=45, ha='right')
            
            # Ajouter les valeurs sur les barres
            for bar, stat in zip(bars, status):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{"✅" if stat == 1 else "❌"}',
                       ha='center', va='bottom')
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def open_settings(self):
        """Ouvrir les paramètres"""
        QMessageBox.information(self, "Paramètres", 
                               "Configuration des paramètres...\n(À implémenter)")

class SNMPWidget(QWidget):
    """Widget de supervision SNMP"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.snmp_manager = SNMPManager(community='supervision')
        self.init_ui()
        self.load_devices()
    
    def init_ui(self):
        """Initialiser l'interface"""
        layout = QVBoxLayout()
        
        # Barre d'outils
        toolbar = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Adresse IP (ex: 10.158.68.201)")
        self.ip_input.setText("10.158.68.201")
        
        self.community_input = QLineEdit()
        self.community_input.setPlaceholderText("Communauté SNMP")
        self.community_input.setText("supervision")
        
        btn_scan = QPushButton("🔍 Scanner")
        btn_scan.clicked.connect(self.scan_device)
        
        btn_refresh = QPushButton("🔄 Actualiser")
        btn_refresh.clicked.connect(self.refresh_devices)
        
        toolbar.addWidget(QLabel("IP:"))
        toolbar.addWidget(self.ip_input)
        toolbar.addWidget(QLabel("Communauté:"))
        toolbar.addWidget(self.community_input)
        toolbar.addWidget(btn_scan)
        toolbar.addWidget(btn_refresh)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # Tableau des équipements
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            "IP", "Nom", "Description", "Statut", "Uptime", "Actions"
        ])
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        layout.addWidget(self.device_table)
        
        # Zone de détails
        details_group = QGroupBox("📋 Informations Détaillées")
        details_layout = QFormLayout()
        
        self.detail_name = QLabel("-")
        self.detail_ip = QLabel("-")
        self.detail_desc = QLabel("-")
        self.detail_uptime = QLabel("-")
        self.detail_location = QLabel("-")
        
        details_layout.addRow("Nom:", self.detail_name)
        details_layout.addRow("IP:", self.detail_ip)
        details_layout.addRow("Description:", self.detail_desc)
        details_layout.addRow("Uptime:", self.detail_uptime)
        details_layout.addRow("Localisation:", self.detail_location)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        self.setLayout(layout)
        
        # Connecter la sélection de ligne
        self.device_table.itemSelectionChanged.connect(self.show_device_details)
    
    def load_devices(self):
        """Charger la liste des équipements"""
        devices = self.snmp_manager.discover_devices()
        self.device_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            # IP
            self.device_table.setItem(row, 0, QTableWidgetItem(device['ip']))
            
            # Nom
            self.device_table.setItem(row, 1, QTableWidgetItem(device['name']))
            
            # Description
            desc = device.get('description', 'N/A')
            self.device_table.setItem(row, 2, QTableWidgetItem(desc))
            
            # Statut
            status_item = QTableWidgetItem(device.get('status', 'N/A'))
            if '✅' in device.get('status', ''):
                status_item.setBackground(QColor('#d5f4e6'))
            else:
                status_item.setBackground(QColor('#f8d7da'))
            self.device_table.setItem(row, 3, status_item)
            
            # Uptime
            self.device_table.setItem(row, 4, QTableWidgetItem(device.get('uptime', 'N/A')))
            
            # Bouton d'action
            btn_widget = QWidget()
            btn_layout = QHBoxLayout()
            btn_layout.setContentsMargins(4, 4, 4, 4)
            
            btn_monitor = QPushButton("📊")
            btn_monitor.setToolTip("Surveiller")
            btn_monitor.clicked.connect(lambda checked, ip=device['ip']: self.monitor_device(ip))
            btn_monitor.setMaximumWidth(30)
            
            btn_ping = QPushButton("📡")
            btn_ping.setToolTip("Tester")
            btn_ping.clicked.connect(lambda checked, ip=device['ip']: self.test_device(ip))
            btn_ping.setMaximumWidth(30)
            
            btn_layout.addWidget(btn_monitor)
            btn_layout.addWidget(btn_ping)
            btn_layout.addStretch()
            
            btn_widget.setLayout(btn_layout)
            self.device_table.setCellWidget(row, 5, btn_widget)
        
        self.device_table.resizeColumnsToContents()
    
    def scan_device(self):
        """Scanner un équipement spécifique"""
        ip = self.ip_input.text().strip()
        community = self.community_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Erreur", "Veuillez entrer une adresse IP")
            return
        
        QMessageBox.information(self, "Scan", 
                               f"Scan de {ip} avec communauté '{community}'...")
        
        try:
            manager = SNMPManager(community=community)
            info = manager.get_system_info(ip)
            
            if 'sysName' in info:
                QMessageBox.information(self, "Résultat",
                                       f"Équipement trouvé:\n"
                                       f"Nom: {info.get('sysName', 'N/A')}\n"
                                       f"Description: {info.get('sysDescr', 'N/A')}")
            else:
                QMessageBox.warning(self, "Résultat",
                                  f"Aucun équipement SNMP trouvé sur {ip}")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur de scan: {str(e)}")
    
    def refresh_devices(self):
        """Rafraîchir la liste des équipements"""
        self.load_devices()
        QMessageBox.information(self, "Actualisation", 
                               "Liste des équipements actualisée")
    
    def show_device_details(self):
        """Afficher les détails de l'équipement sélectionné"""
        selected = self.device_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        ip = self.device_table.item(row, 0).text()
        
        try:
            info = self.snmp_manager.get_system_info(ip)
            
            self.detail_name.setText(info.get('sysName', 'N/A'))
            self.detail_ip.setText(ip)
            self.detail_desc.setText(info.get('sysDescr', 'N/A')[:100] + "...")
            self.detail_uptime.setText(info.get('sysUpTime', 'N/A'))
            self.detail_location.setText(info.get('sysLocation', 'N/A'))
            
        except Exception as e:
            print(f"Erreur détails: {e}")
    
    def monitor_device(self, ip):
        """Surveiller un équipement"""
        QMessageBox.information(self, "Surveillance",
                               f"Démarrage de la surveillance de {ip}...")
    
    def test_device(self, ip):
        """Tester un équipement"""
        try:
            info = self.snmp_manager.get_system_info(ip)
            QMessageBox.information(self, "Test",
                                   f"Test réussi!\n"
                                   f"IP: {ip}\n"
                                   f"Nom: {info.get('sysName', 'N/A')}\n"
                                   f"Réponse: OK")
        except Exception as e:
            QMessageBox.critical(self, "Test échoué",
                               f"Impossible de contacter {ip}\nErreur: {str(e)}")

class NagiosWidget(QWidget):
    """Widget de supervision Nagios"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nagios_client = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        self.init_ui()
        self.load_status()
    
    def init_ui(self):
        """Initialiser l'interface"""
        layout = QVBoxLayout()
        
        # En-tête
        header = QLabel("⚠️ SUPERVISION NAGIOS")
        header.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #c0392b;
            padding: 10px;
            background-color: #fadbd8;
            border-radius: 5px;
        """)
        layout.addWidget(header)
        
        # Boutons de contrôle
        control_layout = QHBoxLayout()
        
        btn_refresh = QPushButton("🔄 Actualiser Nagios")
        btn_refresh.clicked.connect(self.load_status)
        
        btn_alerts = QPushButton("📢 Voir les alertes")
        btn_alerts.clicked.connect(self.show_alerts)
        
        btn_services = QPushButton("🔧 Services")
        btn_services.clicked.connect(self.show_services)
        
        control_layout.addWidget(btn_refresh)
        control_layout.addWidget(btn_alerts)
        control_layout.addWidget(btn_services)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Statut de connexion
        self.status_label = QLabel("Test de connexion en cours...")
        layout.addWidget(self.status_label)
        
        # Tableau des hôtes
        self.host_table = QTableWidget()
        self.host_table.setColumnCount(4)
        self.host_table.setHorizontalHeaderLabels([
            "Hôte", "Adresse IP", "Statut", "Dernière vérification"
        ])
        self.host_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        layout.addWidget(self.host_table)
        
        self.setLayout(layout)
    
    def load_status(self):
        """Charger le statut Nagios"""
        try:
            if not self.nagios_client.test_connection():
                self.status_label.setText("❌ Nagios inaccessible")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                return
            
            self.status_label.setText("✅ Nagios connecté")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            
            # Charger les hôtes
            hosts = self.nagios_client.get_host_status()
            self.host_table.setRowCount(len(hosts))
            
            for row, host in enumerate(hosts):
                # Nom
                self.host_table.setItem(row, 0, QTableWidgetItem(host['name']))
                
                # IP
                self.host_table.setItem(row, 1, QTableWidgetItem(host.get('address', 'N/A')))
                
                # Statut
                status_item = QTableWidgetItem(host.get('status_text', 'UNKNOWN'))
                
                # Colorer selon le statut
                status = host.get('status', 3)
                if status == 0:  # UP
                    status_item.setBackground(QColor('#d5f4e6'))
                elif status == 1:  # DOWN
                    status_item.setBackground(QColor('#f8d7da'))
                elif status == 2:  # UNREACHABLE
                    status_item.setBackground(QColor('#fff3cd'))
                
                self.host_table.setItem(row, 2, status_item)
                
                # Dernière vérification
                last_check = host.get('last_check', 'N/A')
                self.host_table.setItem(row, 3, QTableWidgetItem(last_check))
            
            self.host_table.resizeColumnsToContents()
            
        except Exception as e:
            self.status_label.setText(f"❌ Erreur: {str(e)}")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
    
    def show_alerts(self):
        """Afficher les alertes"""
        try:
            alerts = self.nagios_client.get_alerts(hours=24)
            
            if alerts:
                alert_text = "📢 Alertes des dernières 24h:\n\n"
                for alert in alerts[:10]:  # Limiter à 10 alertes
                    alert_text += f"• {alert.get('host_name', 'N/A')}: {alert.get('message', 'N/A')}\n"
                
                QMessageBox.information(self, "Alertes Nagios", alert_text)
            else:
                QMessageBox.information(self, "Alertes Nagios", 
                                       "✅ Aucune alerte dans les dernières 24h")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de récupérer les alertes: {str(e)}")
    
    def show_services(self):
        """Afficher les services"""
        QMessageBox.information(self, "Services Nagios",
                               "Liste des services...\n(À implémenter complètement)")

class MainWindow(QMainWindow):
    """Fenêtre principale de l'application"""
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Initialiser l'interface"""
        self.setWindowTitle("🌐 Plateforme de Supervision Réseau")
        self.setGeometry(100, 100, 1200, 800)
        
        # Barre de menu
        self.create_menu_bar()
        
        # Barre d'outils
        self.create_toolbar()
        
        # Widget central avec onglets
        self.tab_widget = QTabWidget()
        
        # Créer les onglets
        self.dashboard_tab = DashboardWidget()
        self.snmp_tab = SNMPWidget()
        self.nagios_tab = NagiosWidget()
        
        self.tab_widget.addTab(self.dashboard_tab, "🏠 Tableau de bord")
        self.tab_widget.addTab(self.snmp_tab, "📡 Supervision SNMP")
        self.tab_widget.addTab(self.nagios_tab, "⚠️ Nagios")
        
        self.setCentralWidget(self.tab_widget)
        
        # Barre de statut
        self.status_bar = self.statusBar()
        self.status_bar.showMessage('Prêt - ' + datetime.now().strftime("%H:%M:%S"))
        
        # Timer pour les mises à jour
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(10000)  # Toutes les 10 secondes
        
        # Style
        self.apply_style()
    
    def create_menu_bar(self):
        """Créer la barre de menu"""
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu('Fichier')
        
        exit_action = QAction('Quitter', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Menu Vue
        view_menu = menubar.addMenu('Vue')
        
        dark_action = QAction('Mode Sombre', self, checkable=True)
        dark_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(dark_action)
        
        # Menu Aide
        help_menu = menubar.addMenu('Aide')
        
        about_action = QAction('À propos', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Créer la barre d'outils"""
        toolbar = self.addToolBar('Outils')
        
        refresh_action = QAction(QIcon.fromTheme('view-refresh'), 'Rafraîchir tout', self)
        refresh_action.triggered.connect(self.refresh_all)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        scan_action = QAction(QIcon.fromTheme('edit-find'), 'Scanner réseau', self)
        scan_action.triggered.connect(self.scan_network)
        toolbar.addAction(scan_action)
        
        capture_action = QAction(QIcon.fromTheme('media-record'), 'Capturer', self)
        capture_action.triggered.connect(self.start_capture)
        toolbar.addAction(capture_action)
    
    def apply_style(self):
        """Appliquer le style à l'interface"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                font-weight: bold;
            }
            QTableWidget {
                gridline-color: #dddddd;
                alternate-background-color: #f9f9f9;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
    
    def refresh_all(self):
        """Rafraîchir toutes les données"""
        self.status_bar.showMessage('Rafraîchissement en cours...')
        
        # Rafraîchir chaque onglet
        self.dashboard_tab.refresh_data()
        self.snmp_tab.refresh_devices()
        self.nagios_tab.load_status()
        
        QTimer.singleShot(1000, lambda: self.status_bar.showMessage('Données rafraîchies'))
    
    def scan_network(self):
        """Scanner le réseau"""
        self.status_bar.showMessage('Scan réseau en cours...')
        
        # Utiliser l'onglet SNMP pour scanner
        self.tab_widget.setCurrentWidget(self.snmp_tab)
        self.snmp_tab.scan_device()
    
    def start_capture(self):
        """Démarrer une capture réseau"""
        QMessageBox.information(self, "Capture réseau",
                               "Démarrage de la capture...\n(À implémenter avec Wireshark)")
    
    def toggle_dark_mode(self, checked):
        """Basculer entre mode sombre et clair"""
        if checked:
            dark_style = """
                QMainWindow {
                    background-color: #2b2b2b;
                    color: #ffffff;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                    background-color: #3c3c3c;
                }
                QTabBar::tab {
                    background-color: #555555;
                    color: white;
                    padding: 10px;
                }
                QTabBar::tab:selected {
                    background-color: #3c3c3c;
                    font-weight: bold;
                }
                QGroupBox {
                    color: white;
                    border: 1px solid #555555;
                }
                QLabel {
                    color: white;
                }
                QTableWidget {
                    background-color: #3c3c3c;
                    color: white;
                    gridline-color: #555555;
                }
                QLineEdit, QComboBox {
                    background-color: #4a4a4a;
                    color: white;
                    border: 1px solid #555555;
                }
            """
            self.setStyleSheet(dark_style)
        else:
            self.apply_style()
    
    def update_status(self):
        """Mettre à jour la barre de statut"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.status_bar.showMessage(f'Dernière mise à jour: {current_time}')
    
    def show_about(self):
        """Afficher la boîte À propos"""
        QMessageBox.about(self, "À propos",
                         "Plateforme de Supervision Réseau\n\n"
                         "Version 1.0\n"
                         "Développé pour le projet de supervision réseau\n"
                         "avec SNMP, Nagios et Wireshark\n\n"
                         "© 2024")

def main():
    """Fonction principale"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Style moderne
    
    # Définir l'icône de l'application
    app.setWindowIcon(QIcon.fromTheme('network-server'))
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()