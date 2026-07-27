import socket
import psutil
from typing import List, Dict, Tuple
import json
import subprocess
import threading
import time

class NetworkMonitor:
    """Surveille le trafic réseau sortant suspect"""
    
    def __init__(self):
        self.suspicious_ports = [4444, 6666, 8080, 1337, 31337]
        self.suspicious_domains = ['pastebin.com', 'dropbox.com', 'discord.com']
        self.known_malicious_ips = set()  # À charger depuis une source externe
        
    def get_active_connections(self) -> List[Dict]:
        """Récupère toutes les connexions réseau actives"""
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' or conn.status == 'SYN_SENT':
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    connections.append({
                        'pid': conn.pid,
                        'process': proc.name() if proc else 'Unknown',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '0.0.0.0:0',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '0.0.0.0:0',
                        'status': conn.status,
                        'exe_path': proc.exe() if proc else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        return connections
    
    def detect_data_exfiltration(self, connections: List[Dict]) -> List[Dict]:
        """Détecte les tentatives d'exfiltration de données"""
        alerts = []
        
        for conn in connections:
            risk = 0
            
            # Vérifier les ports suspects
            if conn['remote_addr']:
                remote_port = int(conn['remote_addr'].split(':')[-1])
                if remote_port in self.suspicious_ports:
                    risk += 30
                    
                # Vérifier les IPs privées (exfiltration externe)
                remote_ip = conn['remote_addr'].split(':')[0]
                if not remote_ip.startswith(('192.168.', '10.', '172.16.')):
                    risk += 10
                    
                # Vérifier les domaines connus d'exfiltration
                # (à faire avec une résolution DNS inversée)
                
            # Si le processus est suspect
            if conn['process'].lower() in ['python.exe', 'powershell.exe', 'cmd.exe']:
                if conn['remote_addr']:
                    risk += 20
                    
            # Alerte si risque élevé
            if risk >= 40:
                alerts.append({
                    'connection': conn,
                    'risk_score': risk,
                    'reason': 'Potentielle exfiltration de données'
                })
                
        return alerts
    
    def monitor_dns_queries(self, timeout: int = 30) -> List[Dict]:
        """Surveille les requêtes DNS sortantes (nécessite pyshark ou scapy)"""
        # Version simplifiée avec nslookup
        suspicious_queries = []
        
        try:
            # Simuler une surveillance DNS
            # Dans un vrai lab, on utiliserait scapy ou pyshark
            domains_to_check = ['google.com', 'microsoft.com', 'windows.com']
            for domain in domains_to_check:
                try:
                    ip = socket.gethostbyname(domain)
                    # Vérifier si le domaine est dans notre liste de suspicion
                    if any(sus in domain for sus in self.suspicious_domains):
                        suspicious_queries.append({
                            'domain': domain,
                            'ip': ip,
                            'timestamp': time.time()
                        })
                except:
                    continue
        except:
            pass
            
        return suspicious_queries
    
    def check_network_anomalies(self) -> Dict:
        """Détecte des anomalies réseau globales"""
        anomalies = {
            'unusual_ports': [],
            'high_traffic_processes': [],
            'external_connections': []
        }
        
        connections = self.get_active_connections()
        
        # Group by PID pour détecter les processus avec trop de connexions
        pid_count = {}
        for conn in connections:
            if conn['pid']:
                pid_count[conn['pid']] = pid_count.get(conn['pid'], 0) + 1
                
        for pid, count in pid_count.items():
            if count > 10:  # Un processus normal n'ouvre pas autant de connexions
                try:
                    proc = psutil.Process(pid)
                    anomalies['high_traffic_processes'].append({
                        'pid': pid,
                        'name': proc.name(),
                        'connections': count
                    })
                except:
                    pass
                    
        # Détecter les connexions externes
        for conn in connections:
            if conn['remote_addr']:
                remote_ip = conn['remote_addr'].split(':')[0]
                if not remote_ip.startswith(('192.168.', '10.', '172.16.')):
                    anomalies['external_connections'].append(conn)
                    
        return anomalies
