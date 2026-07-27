import ctypes
from ctypes import wintypes, byref, WinError
import psutil
from typing import List, Dict

class HookScanner:
    """Détecte les hooks clavier/souris via l'API Windows"""
    
    # Constantes Windows
    WH_KEYBOARD_LL = 13
    WH_MOUSE_LL = 14
    WH_KEYBOARD = 2
    WH_MOUSE = 7
    
    def __init__(self):
        self.user32 = ctypes.windll.user32
        self.kernel32 = ctypes.windll.kernel32
        
    def get_all_hooks(self) -> List[Dict]:
        """Récupère la liste des hooks système actifs"""
        hooks = []
        
        # Parcourir tous les processus
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Vérifier les hooks pour ce processus
                hook_info = self._check_process_hooks(proc.info['pid'])
                if hook_info:
                    hooks.append({
                        'pid': proc.info['pid'],
                        'process': proc.info['name'],
                        'hooks': hook_info
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return hooks
    
    def _check_process_hooks(self, pid: int) -> List[str]:
        """Vérifie si un processus spécifique a des hooks actifs"""
        detected = []
        
        try:
            # Tenter d'ouvrir le processus
            hProcess = self.kernel32.OpenProcess(0x1000, False, pid)
            if not hProcess:
                return detected
                
            # Vérifier les threads du processus
            thread_ids = self._get_thread_ids(pid)
            for tid in thread_ids:
                # Vérifier si ce thread a un hook clavier
                if self._thread_has_hook(tid, self.WH_KEYBOARD_LL):
                    detected.append(f"KeyboardHook_LL (TID:{tid})")
                if self._thread_has_hook(tid, self.WH_MOUSE_LL):
                    detected.append(f"MouseHook_LL (TID:{tid})")
                    
            self.kernel32.CloseHandle(hProcess)
            
        except Exception:
            pass
            
        return detected
    
    def _get_thread_ids(self, pid: int) -> List[int]:
        """Récupère les IDs des threads d'un processus"""
        threads = []
        try:
            for proc in psutil.process_iter(['pid']):
                if proc.info['pid'] == pid:
                    for thread in proc.threads():
                        threads.append(thread.id)
                    break
        except Exception:
            pass
        return threads
    
    def _thread_has_hook(self, tid: int, hook_type: int) -> bool:
        """Vérifie si un thread spécifique a un hook du type donné"""
        # Méthode indirecte : vérifier si le thread a des messages en attente
        # qui pourraient indiquer un hook
        try:
            # Utiliser GetQueueStatus pour détecter des messages clavier/souris
            result = self.user32.GetQueueStatus(0xFFFF)
            if result & 0x0001:  # QS_KEY
                return True
        except:
            pass
        return False
    
    def scan_suspicious_dlls(self) -> List[Dict]:
        """Scanne les processus pour des DLL connues de keylogging"""
        suspicious_dlls = [
            'easyhook.dll', 'globalmousekeyboardhook.dll',
            'keylogger.dll', 'pynput.dll', 'hook.dll'
        ]
        
        found = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
            try:
                for dll in proc.memory_maps():
                    dll_name = dll.path.lower()
                    for susp in suspicious_dlls:
                        if susp in dll_name:
                            found.append({
                                'pid': proc.pid,
                                'process': proc.name(),
                                'dll': dll.path
                            })
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return found
