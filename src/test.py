from detector import HookScanner, ProcessAnalyzer, NetworkMonitor, FileScanner

print("=== SCAN DE HOOKS ===")
hook = HookScanner()
print(hook.scan_suspicious_dlls())

print("\n=== SCAN DES PROCESSUS ===")
proc = ProcessAnalyzer()
processes = proc.get_all_processes()
for p in processes[:5]:  # Affiche les 5 premiers
    print(f"PID {p['pid']}: {p['name']} - Score {proc.calculate_risk_score(p)}")

print("\n=== SCAN RÉSEAU ===")
net = NetworkMonitor()
conns = net.get_active_connections()
print(f"Connexions actives : {len(conns)}")
print(net.detect_data_exfiltration(conns)[:3])

print("\n=== SCAN DES FICHIERS ===")
fs = FileScanner()
logs = fs.scan_for_log_files()
print(f"Fichiers logs suspects : {len(logs)}")
dlls = fs.find_suspicious_dlls()
print(f"DLL suspectes : {len(dlls)}")
