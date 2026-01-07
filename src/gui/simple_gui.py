#!/usr/bin/env python3
"""
Interface graphique simplifiée pour la supervision réseau
Version légère et rapide
"""

import sys
import os
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import threading
import time

# Import nos modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.snmp_manager import SNMPManager
from core.nagios_client import NagiosClient

class SimpleSupervisorGUI(QMainWindow):
    """Interface graphique simplifiée"""
    
    def __init__(self):
        super().__init__()
        self.snmp_manager = SNMPManager(community='supervision')
        self.nagios_client = NagiosClient(
            base_url="http://10.158.68.200",
            username="nagiosadmin",
            password="admin123"
        )
        self.init_ui()
        self.start_monitoring()
    
    def init_ui(self):
        """Initialiser l'interface"""
        self.setWindowTitle("🔍 Superviseur Réseau Simple")
        self.setGeometry(100, 100, 900, 700)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # En-tête
        header = QLabel("🚀 SUPERVISEUR RÉSEAU")
        header.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding: 15px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3498db, stop:1 #2ecc71);
                color: white;
                border-radius: 10px;
                margin: 5px;
            }
        """)
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        # Cartes d'état
        self.status_cards = self.create_status_cards()
        main_layout.addLayout(self.status_cards)
        
        # Tableau des équipements
        self.create_device_table()
        main_layout.addWidget(self.device_table)
        
        # Boutons d'action
        self.create_action_buttons()
        main_layout.addLayout(self.button_layout)
        
        # Logs en bas
        self.create_log_area()
        main_layout.addWidget(self.log_widget)
        
        # Barre de statut
        self.statusBar().showMessage('Prêt - ' + datetime.now().strftime("%H:%M:%S"))
        
        # Timer de mise à jour
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(30000)  # 30 secondes
        
        # Style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                alternate-background-color: #f8f9fa;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 15px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c6ea4;
            }
            QPushButton#danger {
                background-color: #e74c3c;
            }
            QPushButton#danger:hover {
                background-color: #c0392b;
            }
            QPushButton#success {
                background-color: #2ecc71;
            }
            QPushButton#success:hover {
                background-color: #27ae60;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                font-family: 'Monospace';
                font-size: 12px;
            }
        """)
    
    def create_status_cards(self):
        """Créer les cartes d'état"""
        cards_layout = QHBoxLayout()
        
        # Carte Nagios
        self.nagios_card = QGroupBox("⚠️ Nagios")
        nagios_layout = QVBoxLayout()
        self.nagios_status = QLabel("Test en cours...")
        self.nagios_status.setAlignment(Qt.AlignCenter)
        self.nagios_status.setStyleSheet("font-size: 16px; font-weight: bold;")
        nagios_layout.addWidget(self.nagios_status)
        self.nagios_card.setLayout(nagios_layout)
        
        # Carte Équipements
        self.device_card = QGroupBox("🖥️ Équipements")
        device_layout = QVBoxLayout()
        self.device_status = QLabel("Scan en cours...")
        self.device_status.setAlignment(Qt.AlignCenter)
        self.device_status.setStyleSheet("font-size: 16px; font-weight: bold;")
        device_layout.addWidget(self.device_status)
        self.device_card.setLayout(device_layout)
        
        # Carte Performance
        self.perf_card = QGroupBox("📈 Performance")
        perf_layout = QVBoxLayout()
        self.perf_status = QLabel("Chargement...")
        self.perf_status.setAlignment(Qt.AlignCenter)
        self.perf_status.setStyleSheet("font-size: 16px; font-weight: bold;")
        perf_layout.addWidget(self.perf_status)
        self.perf_card.setLayout(perf_layout)
        
        cards_layout.addWidget(self.nagios_card)
        cards_layout.addWidget(self.device_card)
        cards_layout.addWidget(self.perf_card)
        
        return cards_layout
    
    def create_device_table(self):
        """Créer le tableau des équipements"""
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels([
            "IP", "Nom", "Statut", "Uptime", "Actions"
        ])
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Ajuster la largeur des colonnes
        header = self.device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
    
    def create_action_buttons(self):
        """Créer les boutons d'action"""
        self.button_layout = QHBoxLayout()
        
        # Bouton Scan
        btn_scan = QPushButton("🔍 Scanner le réseau")
        btn_scan.clicked.connect(self.scan_network)
        btn_scan.setObjectName("success")
        
        # Bouton Nagios
        btn_nagios = QPushButton("⚠️ Vérifier Nagios")
        btn_nagios.clicked.connect(self.check_nagios)
        
        # Bouton Rafraîchir
        btn_refresh = QPushButton("🔄 Actualiser")
        btn_refresh.clicked.connect(self.refresh_all)
        
        # Bouton Quitter
        btn_quit = QPushButton("❌ Quitter")
        btn_quit.clicked.connect(self.close)
        btn_quit.setObjectName("danger")
        
        self.button_layout.addWidget(btn_scan)
        self.button_layout.addWidget(btn_nagios)
        self.button_layout.addWidget(btn_refresh)
        self.button_layout.addStretch()
        self.button_layout.addWidget(btn_quit)
    
    def create_log_area(self):
        """Créer la zone de logs"""
        self.log_widget = QGroupBox("📝 Logs d'activité")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        
        # Bouton effacer logs
        btn_clear = QPushButton("🗑️ Effacer les logs")
        btn_clear.clicked.connect(lambda: self.log_text.clear())
        btn_clear.setMaximumWidth(150)
        
        log_layout.addWidget(self.log_text)
        log_layout.addWidget(btn_clear, alignment=Qt.AlignRight)
        
        self.log_widget.setLayout(log_layout)
    
    def start_monitoring(self):
        """Démarrer la surveillance en arrière-plan"""
        self.monitor_thread = threading.Thread(target=self.update_monitoring, daemon=True)
        self.monitor_thread.start()
    
    def update_monitoring(self):
        """Mettre à jour les données périodiquement"""
        while True:
            try:
                self.update_status()
                time.sleep(60)  # Actualiser toutes les minutes
            except Exception as e:
                self.log_message(f"Erreur monitoring: {str(e)}")
                time.sleep(10)
    
    def update_status(self):
        """Mettre à jour tous les statuts"""
        try:
            # 1. Vérifier Nagios
            nagios_ok = self.nagios_client.test_connection()
            if nagios_ok:
                hosts = self.nagios_client.get_host_status()
                online_hosts = len([h for h in hosts if h.get('status', 1) == 0])
                self.nagios_status.setText(f"✅ {online_hosts}/{len(hosts)} hôtes")
                self.nagios_card.setStyleSheet("QGroupBox { border: 2px solid #2ecc71; }")
            else:
                self.nagios_status.setText("❌ Hors ligne")
                self.nagios_card.setStyleSheet("QGroupBox { border: 2px solid #e74c3c; }")
            
            # 2. Scanner les équipements
            devices = self.snmp_manager.discover_devices()
            online_devices = len([d for d in devices if '✅' in d.get('status', '')])
            self.device_status.setText(f"📡 {online_devices}/{len(devices)} en ligne")
            
            # Mettre à jour le tableau
            self.update_device_table(devices)
            
            # 3. Performance
            if devices:
                avg_uptime = len(devices)  # Simplifié pour l'exemple
                self.perf_status.setText(f"📊 {avg_uptime} équipements")
                self.perf_card.setStyleSheet("QGroupBox { border: 2px solid #3498db; }")
            
            # 4. Mettre à jour la barre de statut
            self.statusBar().showMessage(f'Dernière mise à jour: {datetime.now().strftime("%H:%M:%S")}')
            
        except Exception as e:
            self.log_message(f"Erreur mise à jour: {str(e)}")
    
    def update_device_table(self, devices):
        """Mettre à jour le tableau des équipements"""
        self.device_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            # IP
            ip_item = QTableWidgetItem(device['ip'])
            self.device_table.setItem(row, 0, ip_item)
            
            # Nom
            name_item = QTableWidgetItem(device['name'])
            self.device_table.setItem(row, 1, name_item)
            
            # Statut
            status = device.get('status', '❓')
            status_item = QTableWidgetItem(status)
            
            # Colorer selon le statut
            if '✅' in status:
                status_item.setBackground(QColor('#d5f4e6'))
                status_item.setForeground(QColor('#155724'))
            elif '⚠️' in status:
                status_item.setBackground(QColor('#fff3cd'))
                status_item.setForeground(QColor('#856404'))
            else:
                status_item.setBackground(QColor('#f8d7da'))
                status_item.setForeground(QColor('#721c24'))
            
            self.device_table.setItem(row, 2, status_item)
            
            # Uptime
            uptime = device.get('uptime', 'N/A')
            if len(uptime) > 30:
                uptime = uptime[:30] + "..."
            self.device_table.setItem(row, 3, QTableWidgetItem(uptime))
            
            # Boutons d'action
            btn_widget = QWidget()
            btn_layout = QHBoxLayout()
            btn_layout.setContentsMargins(4, 4, 4, 4)
            
            btn_info = QPushButton("ℹ️")
            btn_info.setToolTip("Informations")
            btn_info.setMaximumWidth(30)
            btn_info.clicked.connect(lambda checked, ip=device['ip']: self.show_device_info(ip))
            
            btn_ping = QPushButton("📡")
            btn_ping.setToolTip("Tester")
            btn_ping.setMaximumWidth(30)
            btn_ping.clicked.connect(lambda checked, ip=device['ip']: self.test_device(ip))
            
            btn_layout.addWidget(btn_info)
            btn_layout.addWidget(btn_ping)
            btn_layout.addStretch()
            
            btn_widget.setLayout(btn_layout)
            self.device_table.setCellWidget(row, 4, btn_widget)
    
    def scan_network(self):
        """Scanner le réseau"""
        self.log_message("🔍 Démarrage du scan réseau...")
        
        thread = threading.Thread(target=self.perform_scan)
        thread.start()
    
    def perform_scan(self):
        """Effectuer le scan en arrière-plan"""
        try:
            devices = self.snmp_manager.discover_devices()
            online_count = len([d for d in devices if '✅' in d.get('status', '')])
            
            self.log_message(f"✅ Scan terminé: {online_count}/{len(devices)} équipement(s) en ligne")
            
            # Mettre à jour l'interface
            QMetaObject.invokeMethod(self, "update_status", Qt.QueuedConnection)
            
        except Exception as e:
            self.log_message(f"❌ Erreur scan: {str(e)}")
    
    def check_nagios(self):
        """Vérifier Nagios"""
        self.log_message("⚠️ Vérification de Nagios...")
        
        try:
            if self.nagios_client.test_connection():
                alerts = self.nagios_client.get_alerts(hours=1)
                if alerts:
                    self.log_message(f"⚠️ {len(alerts)} alerte(s) dans la dernière heure")
                else:
                    self.log_message("✅ Nagios: Aucune alerte récente")
            else:
                self.log_message("❌ Nagios: Service inaccessible")
                
        except Exception as e:
            self.log_message(f"❌ Erreur Nagios: {str(e)}")
    
    def refresh_all(self):
        """Tout rafraîchir"""
        self.log_message("🔄 Actualisation des données...")
        self.update_status()
        self.log_message("✅ Données actualisées")
    
    def show_device_info(self, ip):
        """Afficher les informations d'un équipement"""
        try:
            info = self.snmp_manager.get_system_info(ip)
            
            msg = QMessageBox(self)
            msg.setWindowTitle(f"📋 Informations - {ip}")
            msg.setIcon(QMessageBox.Information)
            
            details = f"""
            <b>Adresse IP:</b> {ip}<br>
            <b>Nom:</b> {info.get('sysName', 'N/A')}<br>
            <b>Description:</b> {info.get('sysDescr', 'N/A')}<br>
            <b>Uptime:</b> {info.get('sysUpTime', 'N/A')}<br>
            <b>Localisation:</b> {info.get('sysLocation', 'N/A')}<br>
            <b>Contact:</b> {info.get('sysContact', 'N/A')}<br>
            """
            
            msg.setText(details)
            msg.exec_()
            
            self.log_message(f"ℹ️ Affichage infos: {ip}")
            
        except Exception as e:
            self.log_message(f"❌ Erreur infos {ip}: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Impossible de récupérer les informations:\n{str(e)}")
    
    def test_device(self, ip):
        """Tester un équipement"""
        self.log_message(f"📡 Test de {ip}...")
        
        try:
            info = self.snmp_manager.get_system_info(ip)
            if 'sysName' in info:
                self.log_message(f"✅ {ip} répond (Nom: {info.get('sysName', 'N/A')})")
                QMessageBox.information(self, "Test réussi",
                                      f"L'équipement {ip} répond correctement.\n"
                                      f"Nom: {info.get('sysName', 'N/A')}")
            else:
                self.log_message(f"❌ {ip} ne répond pas correctement")
                QMessageBox.warning(self, "Test échoué",
                                  f"L'équipement {ip} ne répond pas correctement.")
                
        except Exception as e:
            self.log_message(f"❌ Erreur test {ip}: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Impossible de tester {ip}:\n{str(e)}")
    
    def log_message(self, message):
        """Ajouter un message aux logs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        # Ajouter au widget de logs (thread-safe)
        QMetaObject.invokeMethod(self.log_text, "append",
                               Qt.QueuedConnection,
                               Q_ARG(str, log_entry))
        
        # Défiler vers le bas
        QMetaObject.invokeMethod(self.log_text, "ensureCursorVisible",
                               Qt.QueuedConnection)
        
        # Afficher dans la console aussi
        print(log_entry)
    
    def closeEvent(self, event):
        """Événement de fermeture"""
        reply = QMessageBox.question(self, 'Quitter',
                                    'Êtes-vous sûr de vouloir quitter ?',
                                    QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.log_message("👋 Fermeture de l'application")
            event.accept()
        else:
            event.ignore()

def main():
    """Fonction principale"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Créer et afficher la fenêtre
    window = SimpleSupervisorGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
    