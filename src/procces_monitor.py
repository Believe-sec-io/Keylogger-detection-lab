import psutil

def monitor_process():
    for process in psutil.process_iter(["pid", "name"]):
        try:
            print(f"PID: {process.info['pid']} | Name: {process.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

if __name__ == "__main__":
    monitor_process()
