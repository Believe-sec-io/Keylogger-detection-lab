import os
import re
import hashlib
import psutil
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import time

class FileScanner:
    """Scanne les fichiers suspects (logs, DLLs, exécutables)"""
    
    def __init__(self, watch_dirs: List[str] = None):
        self.watch_dirs = watch_dirs or [
            os.environ.get('APPDATA', ''),
            os.environ.get('TEMP', ''),
            os.environ.get('SYSTEMROOT', '') + '\\Temp',
        ]
        self.suspicious_extensions = ['.log', '.dat', '.tmp', '.key', '.kbd']
        
    def scan_for_log_files(self) -> List[Dict]:
        """Recherche des fichiers de logs suspects pouvant contenir des frappes"""
        suspicious_files = []
        recent_time = datetime.now() - timedelta(hours=24)
        
        for directory in self.watch_dirs:
            if not os.path.exists(directory):
                continue
                
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        # Vérifier les fichiers récents ou modifiés dans les 24h
                        if mtime > recent_time:
                            # Vérifier l'extension
                            ext = os.path.splitext(file)[1].lower()
                            if ext in self.suspicious_extensions:
                                # Vérifier le contenu (à la recherche de patterns de frappes)
                                if self._contains_keyboard_patterns(file_path):
                                    suspicious_files.append({
                                        'path': file_path,
                                        'size': stat.st_size,
                                        'modified': mtime,
                                        'extension': ext,
                                        'reason': 'Fichier log suspect'
                                    })
                    except (PermissionError, OSError):
                        continue
                        
        return suspicious_files
    
    def _contains_keyboard_patterns(self, file_path: str) -> bool:
        """Analyse le contenu d'un fichier pour des motifs de frappes clavier"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Lire les premiers 1KB
                
                # Patterns de keylogging
                patterns = [
                    r'[A-Za-z0-9]+\s*[A-Za-z0-9]+\s*[A-Za-z0-9]+',  # Mots successifs
                    r'Key\s*:?\s*[A-Za-z0-9]+',  # Format "Key: A"
                    r'Pressed\s*[A-Za-z0-9]+',  # Format "Pressed A"
                    r'[0-9]{2}:[0-9]{2}:[0-9]{2}',  # Timestamps
                ]
                
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
        except Exception:
            pass
        return False
    
    def find_suspicious_dlls(self) -> List[Dict]:
        """Recherche des DLL suspectes dans les processus actifs"""
        suspicious = []
        known_suspicious = [
            'easyhook', 'hooklib', 'keyhook', 'globalmousekeyboard',
            'pynput', 'keyboard', 'mousehook'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for dll in proc.memory_maps():
                    dll_name = os.path.basename(dll.path).lower()
                    for sus in known_suspicious:
                        if sus in dll_name:
                            suspicious.append({
                                'pid': proc.pid,
                                'process': proc.name(),
                                'dll_path': dll.path,
                                'reason': f'DLL suspecte: {sus}'
                            })
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return suspicious
    
    def scan_startup_entries(self) -> List[Dict]:
        """Vérifie les clés de registre de démarrage pour des persistences suspectes"""
        suspicious_entries = []
        
        try:
            import winreg
            
            startup_keys = [
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
            ]
            
            for hkey, path in startup_keys:
                try:
                    key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            # Vérifier si la valeur semble suspecte
                            if any(sus in value.lower() for sus in ['keylog', 'hook', 'capture']):
                                suspicious_entries.append({
                                    'hive': 'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM',
                                    'path': path,
                                    'name': name,
                                    'value': value,
                                    'reason': 'Entrée de démarrage suspecte'
                                })
                            index += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        except ImportError:
            pass  # Pas sur Windows
            
        return suspicious_entries
    
    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Calcule le hash SHA256 d'un fichier"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None
