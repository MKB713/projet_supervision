#!/usr/bin/env python3
"""
Interface graphique simplifiée pour la supervision réseau
"""

import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette

class WorkerThread(QThread):
    """Thread pour les opérations longues"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.function(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class SimpleSupervisionGUI(QMainWindow):
    """Interface graphique simplifiée"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.init_workers()
    
    def init_ui(self):
        """Initialiser l'interface utilisateur"""
        self.setWindowTitle("🔧 Plateforme de Supervision Réseau")
        self.setGeometry(100, 100, 900, 700)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        
        # En-tête
        header = QLabel("📡 SUPERVISION RÉSEAU - DASHBOARD")
        header_font = QFont()
        header_font.setPointSize(18)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("padding: 10px; background-color: #2c3e50; color: white;")
        main_layout.addWidget(header)
        
        # Barre d'outils
        toolbar = QHBoxLayout()
        
        self.refresh_btn = QPushButton("🔄 Rafraîchir tout")
        self.refresh_btn.clicked.connect(self.refresh_all)
        self.refresh_btn.setStyleSheet("padding: 8px; font-weight: bold;")
        
        self.discover_btn = QPushButton("🔍 Découvrir équipements")
        self.discover_btn.clicked.connect(self.discover_devices)
        
        self.nagios_btn = QPushButton("⚠️ Vérifier Nagios")
        self.nagios_btn.clicked.connect(self.check_nagios)
        
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.discover_btn)
        toolbar.addWidget(self.nagios_btn)
        toolbar.addStretch()
        
        main_layout.addLayout(toolbar)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Onglets
        self.tabs = QTabWidget()
        
        # Onglet 1: Tableau de bord
        self.dashboard_tab = self.create_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "🏠 Tableau de bord")
        
        # Onglet 2: Équipements
        self.devices_tab = self.create_devices_tab()
        self.tabs.addTab(self.devices_tab, "📡 Équipements")
        
        # Onglet 3: Nagios
        self.nagios_tab = self.create_nagios_tab()
        self.tabs.addTab(self.nagios_tab, "⚠️ Nagios")
        
        main_layout.addWidget(self.tabs)
        
        # Barre de statut
        self.statusBar().showMessage("Prêt")
        
        central_widget.setLayout(main_layout)
        
        # Timer pour auto-refresh
        self.timer = QTimer()
        self.timer.timeout.connect(self.auto_refresh)
        self.timer.start(30000)  # 30 secondes
    
    def create_dashboard_tab(self):
        """Créer l'onglet tableau de bord"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Cartes de statut
        status_layout = QHBoxLayout()
        
        # Carte 1: Équipements
        card1 = QWidget()
        card1.setStyleSheet("background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px;")
        card1_layout = QVBoxLayout()
        
        self.devices_count = QLabel("0")
        self.devices_count.setFont(QFont("Arial", 24, QFont.Bold))
        self.devices_count.setStyleSheet("color: #2c3e50;")
        
        card1_layout.addWidget(QLabel("ÉQUIPEMENTS ACTIFS"))
        card1_layout.addWidget(self.devices_count)
        card1_layout.addWidget(QLabel("Switch-01, Router-01"))
        card1.setLayout(card1_layout)
        
        # Carte 2: Nagios
        card2 = QWidget()
        card2.setStyleSheet("background-color: #e8f4fd; border: 1px solid #b3d7ff; border-radius: 5px; padding: 15px;")
        card2_layout = QVBoxLayout()
        
        self.nagios_status = QLabel("❓")
        self.nagios_status.setFont(QFont("Arial", 24, QFont.Bold))
        
        card2_layout.addWidget(QLabel("STATUT NAGIOS"))
        card2_layout.addWidget(self.nagios_status)
        card2_layout.addWidget(QLabel("http://10.158.68.200/nagios4"))
        card2.setLayout(card2_layout)
        
        # Carte 3: SNMP
        card3 = QWidget()
        card3.setStyleSheet("background-color: #f0f8ff; border: 1px solid #cce5ff; border-radius: 5px; padding: 15px;")
        card3_layout = QVBoxLayout()
        
        self.snmp_status = QLabel("❓")
        self.snmp_status.setFont(QFont("Arial", 24, QFont.Bold))
        
        card3_layout.addWidget(QLabel("STATUT SNMP"))
        card3_layout.addWidget(self.snmp_status)
        card3_layout.addWidget(QLabel("Communauté: supervision"))
        card3.setLayout(card3_layout)
        
        status_layout.addWidget(card1)
        status_layout.addWidget(card2)
        status_layout.addWidget(card3)
        
        layout.addLayout(status_layout)
        
        # Logs en temps réel
        layout.addWidget(QLabel("📋 ACTIVITÉ RÉCENTE:"))
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        self.log_text.setStyleSheet("font-family: 'Courier New'; font-size: 10pt;")
        
        layout.addWidget(self.log_text)
        
        tab.setLayout(layout)
        return tab
    
    def create_devices_tab(self):
        """Créer l'onglet équipements"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Tableau des équipements
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(5)
        self.devices_table.setHorizontalHeaderLabels([
            "IP", "Nom", "Statut", "Description", "Dernière vérification"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.devices_table)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        test_ping_btn = QPushButton("📡 Tester Ping")
        test_ping_btn.clicked.connect(self.test_ping)
        
        test_snmp_btn = QPushButton("🔍 Tester SNMP")
        test_snmp_btn.clicked.connect(self.test_snmp)
        
        button_layout.addWidget(test_ping_btn)
        button_layout.addWidget(test_snmp_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        tab.setLayout(layout)
        return tab
    
    def create_nagios_tab(self):
        """Créer l'onglet Nagios"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Informations Nagios
        info_layout = QVBoxLayout()
        
        self.nagios_info = QTextEdit()
        self.nagios_info.setReadOnly(True)
        self.nagios_info.setPlainText("Chargement des informations Nagios...")
        
        info_layout.addWidget(QLabel("📊 INFORMATIONS NAGIOS:"))
        info_layout.addWidget(self.nagios_info)
        
        layout.addLayout(info_layout)
        
        # Bouton d'accès web
        web_btn = QPushButton("🌐 Ouvrir Nagios dans le navigateur")
        web_btn.clicked.connect(self.open_nagios_web)
        web_btn.setStyleSheet("padding: 10px; background-color: #3498db; color: white; font-weight: bold;")
        
        layout.addWidget(web_btn)
        layout.addStretch()
        
        tab.setLayout(layout)
        return tab
    
    def init_workers(self):
        """Initialiser les threads workers"""
        self.workers = []
    
    def refresh_all(self):
        """Rafraîchir toutes les informations"""
        self.log("🔄 Rafraîchissement en cours...")
        self.discover_devices()
        self.check_nagios()
    
    def discover_devices(self):
        """Découvrir les équipements"""
        self.log("🔍 Découverte des équipements...")
        
        try:
            # Import dynamique
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
            from core.snmp_manager import SNMPManager
            
            # Démarrer le thread
            worker = WorkerThread(self._discover_devices_worker)
            worker.finished.connect(self.on_devices_discovered)
            worker.error.connect(self.on_worker_error)
            worker.start()
            
            self.workers.append(worker)
            
        except ImportError as e:
            self.log(f"❌ Erreur importation: {e}")
            self.show_test_devices()
    
    def _discover_devices_worker(self):
        """Worker pour la découverte d'équipements"""
        from core.snmp_manager import SNMPManager
        manager = SNMPManager(community='supervision')
        return manager.discover_devices()
    
    def on_devices_discovered(self, devices):
        """Callback quand les équipements sont découverts"""
        if devices:
            self.log(f"✅ {len(devices)} équipement(s) trouvé(s)")
            self.update_devices_table(devices)
            self.devices_count.setText(str(len(devices)))
            self.snmp_status.setText("✅")
            self.snmp_status.setStyleSheet("color: green;")
        else:
            self.log("❌ Aucun équipement trouvé")
            self.show_test_devices()
    
    def show_test_devices(self):
        """Afficher des équipements de test"""
        test_devices = [
            {
                'ip': '10.158.68.201',
                'name': 'switch-01',
                'status': '✅ Online',
                'description': 'Switch Simulé',
                'uptime': 'N/A'
            },
            {
                'ip': '10.158.68.202',
                'name': 'router-01',
                'status': '✅ Online',
                'description': 'Routeur Simulé',
                'uptime': 'N/A'
            }
        ]
        
        self.update_devices_table(test_devices)
        self.devices_count.setText("2")
    
    def update_devices_table(self, devices):
        """Mettre à jour le tableau des équipements"""
        self.devices_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            # IP
            ip_item = QTableWidgetItem(device.get('ip', 'N/A'))
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)
            self.devices_table.setItem(row, 0, ip_item)
            
            # Nom
            name_item = QTableWidgetItem(device.get('name', 'N/A'))
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            self.devices_table.setItem(row, 1, name_item)
            
            # Statut
            status_text = device.get('status', '❓ Unknown')
            status_item = QTableWidgetItem(status_text)
            status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
            
            # Colorier en fonction du statut
            if '✅' in status_text or 'UP' in status_text.upper():
                status_item.setForeground(QColor('green'))
            elif '⚠️' in status_text or 'WARNING' in status_text.upper():
                status_item.setForeground(QColor('orange'))
            elif '❌' in status_text or 'DOWN' in status_text.upper():
                status_item.setForeground(QColor('red'))
            
            self.devices_table.setItem(row, 2, status_item)
            
            # Description
            desc_item = QTableWidgetItem(device.get('description', 'N/A')[:50])
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
            self.devices_table.setItem(row, 3, desc_item)
            
            # Dernière vérification
            time_item = QTableWidgetItem(device.get('last_check', datetime.now().strftime("%H:%M:%S")))
            time_item.setFlags(time_item.flags() & ~Qt.ItemIsEditable)
            self.devices_table.setItem(row, 4, time_item)
    
    def check_nagios(self):
        """Vérifier le statut Nagios"""
        self.log("⚠️  Vérification de Nagios...")
        
        try:
            from core.nagios_client import NagiosClient
            
            worker = WorkerThread(self._check_nagios_worker)
            worker.finished.connect(self.on_nagios_checked)
            worker.error.connect(self.on_worker_error)
            worker.start()
            
            self.workers.append(worker)
            
        except ImportError as e:
            self.log(f"❌ Erreur importation Nagios: {e}")
            self.show_nagios_test_info()
    
    def _check_nagios_worker(self):
        """Worker pour vérifier Nagios"""
        from core.nagios_client import NagiosClient
        client = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        
        return {
            'connected': client.test_connection(),
            'hosts': client.get_host_status() if client.test_connection() else []
        }
    
    def on_nagios_checked(self, result):
        """Callback quand Nagios est vérifié"""
        if result['connected']:
            self.log("✅ Nagios connecté")
            self.nagios_status.setText("✅")
            self.nagios_status.setStyleSheet("color: green;")
            
            hosts = result['hosts']
            info_text = "=== STATUT NAGIOS ===\n\n"
            info_text += f"✅ Connecté à: http://10.158.68.200/nagios4\n\n"
            
            if hosts:
                info_text += f"📊 {len(hosts)} hôte(s) surveillé(s):\n\n"
                for host in hosts[:10]:  # Limiter à 10 hôtes
                    status_icon = "✅" if host['status'] == 0 else "⚠️" if host['status'] == 1 else "❌"
                    info_text += f"{status_icon} {host['name']} ({host['address']})\n"
                    info_text += f"   Statut: {host['status_text']}\n\n"
            else:
                info_text += "ℹ️  Aucun hôte trouvé dans Nagios\n"
                info_text += "Vérifiez la configuration Nagios\n"
            
            self.nagios_info.setPlainText(info_text)
            
        else:
            self.log("❌ Nagios non accessible")
            self.nagios_status.setText("❌")
            self.nagios_status.setStyleSheet("color: red;")
            self.show_nagios_test_info()
    
    def show_nagios_test_info(self):
        """Afficher des informations de test pour Nagios"""
        info_text = "=== INFORMATION NAGIOS ===\n\n"
        info_text += "❌ Connexion échouée\n\n"
        info_text += "Pour accéder à Nagios:\n"
        info_text += "URL: http://10.158.68.200/nagios4\n"
        info_text += "Login: nagiosadmin\n"
        info_text += "Password: admin123\n\n"
        info_text += "Vérifiez:\n"
        info_text += "1. La VM Nagios est-elle allumée?\n"
        info_text += "2. L'IP 10.158.68.200 est-elle accessible?\n"
        info_text += "3. Apache tourne-t-il sur Nagios?\n"
        
        self.nagios_info.setPlainText(info_text)
    
    def test_ping(self):
        """Tester le ping"""
        QMessageBox.information(self, "Test Ping", 
            "Fonctionnalité à implémenter\n\n" +
            "Pour tester manuellement:\n" +
            "Terminal → ping 10.158.68.201")
    
    def test_snmp(self):
        """Tester SNMP"""
        QMessageBox.information(self, "Test SNMP",
            "Fonctionnalité à implémenter\n\n" +
            "Pour tester manuellement:\n" +
            "Terminal → snmpwalk -v 2c -c supervision 10.158.68.201 .1.3.6.1.2.1.1.5.0")
    
    def open_nagios_web(self):
        """Ouvrir Nagios dans le navigateur"""
        import webbrowser
        webbrowser.open("http://10.158.68.200/nagios4")
        self.log("🌐 Ouverture de Nagios dans le navigateur...")
    
    def auto_refresh(self):
        """Rafraîchissement automatique"""
        current_tab = self.tabs.currentIndex()
        if current_tab == 1:  # Onglet équipements
            self.discover_devices()
        elif current_tab == 2:  # Onglet Nagios
            self.check_nagios()
    
    def on_worker_error(self, error_msg):
        """Gérer les erreurs des workers"""
        self.log(f"❌ Erreur: {error_msg}")
    
    def log(self, message):
        """Ajouter un message au log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        
        # Garder seulement les 50 dernières lignes
        lines = self.log_text.toPlainText().split('\n')
        if len(lines) > 50:
            self.log_text.setPlainText('\n'.join(lines[-50:]))
        
        # Mettre à jour la barre de statut
        self.statusBar().showMessage(message, 5000)

def main():
    """Point d'entrée principal"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Style simple
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f5f5f5;
        }
        QTabWidget::pane {
            border: 1px solid #cccccc;
            background-color: white;
        }
        QTabBar::tab {
            background-color: #e0e0e0;
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: white;
            font-weight: bold;
        }
        QTableWidget {
            gridline-color: #dddddd;
        }
        QTableWidget::item {
            padding: 5px;
        }
    """)
    
    window = SimpleSupervisionGUI()
    window.show()
    
    # Rafraîchissement initial
    window.discover_devices()
    window.check_nagios()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()