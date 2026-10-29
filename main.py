"""
AdShield DNS - Network-Wide DNS Sinkhole AdBlocker for Windows
Main Entrypoint
"""

import os
import sys
import time
import argparse
import ctypes
import threading
import signal

# Ensure Windows console doesn't crash on emojis
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from windows_utils import prevent_sleep, allow_sleep, is_admin, get_lan_ips
from config_manager import ConfigManager
from blocklist_manager import BlocklistManager
from dns_engine import DNSEngine
from web_server import WebServer
from tray_app import TrayApp

def get_base_dir() -> str:
    """Get base directory whether running from script or PyInstaller frozen bundle."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_resource_dir() -> str:
    """Get path to static resources (unpacked in _MEIPASS by PyInstaller)."""
    if getattr(sys, '_MEIPASS', False):
        return sys._MEIPASS
    return get_base_dir()

def elevate_privileges():
    """Relaunch the application with Administrator privileges via UAC."""
    try:
        if getattr(sys, 'frozen', False):
            exe = sys.executable
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        else:
            exe = sys.executable
            params = f'"{os.path.abspath(sys.argv[0])}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])

        print("[Main] Requesting Administrator privileges...")
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if ret > 32:
            sys.exit(0) # Elevated instance launched successfully
    except Exception as e:
        print(f"[Main] Elevation error: {e}")

def main():
    parser = argparse.ArgumentParser(description="AdShield DNS - Windows Sinkhole AdBlocker")
    parser.add_argument("--no-tray", action="store_true", help="Jalankan di latar belakang tanpa ikon tray")
    parser.add_argument("--no-elevate", action="store_true", help="Jangan meminta UAC elevation otomatis")
    args = parser.parse_args()

    print("=" * 60)
    print("   🛡️  AdShield DNS - Network-Wide AdBlocker for Windows")
    print("=" * 60)

    # 1. Check Administrator privilege (needed for port 53)
    if not is_admin() and not args.no_elevate:
        print("[Main] Perhatian: Port 53 memerlukan hak akses Administrator.")
        elevate_privileges()
        # If user cancels UAC, continue anyway to try binding

    # 2. Prevent Windows from entering Sleep/Standby while active
    prevent_sleep()
    print("[Main] Pencegah Sleep Windows aktif (PC akan tetap terjaga).")

    # 3. Setup Directories
    base_dir = get_base_dir()
    res_dir = get_resource_dir()

    data_dir = os.path.join(base_dir, "data")
    static_dir = os.path.join(res_dir, "static")

    os.makedirs(data_dir, exist_ok=True)

    # Ensure bundled default blocklist is extracted to data dir if missing
    bundled_default_list = os.path.join(res_dir, "data", "default_blocklist.txt")
    target_default_list = os.path.join(data_dir, "default_blocklist.txt")
    if os.path.exists(bundled_default_list) and not os.path.exists(target_default_list):
        try:
            import shutil
            shutil.copy2(bundled_default_list, target_default_list)
            print(f"[Main] Ekstrak blocklist bawaan ke {target_default_list}")
        except Exception as e:
            print(f"[Main] Warning: Gagal ekstrak blocklist: {e}")

    # If static dir is in data or base dir, ensure fallback
    if not os.path.exists(static_dir):
        static_dir = os.path.join(base_dir, "static")

    # 4. Initialize Core Managers
    config_mgr = ConfigManager(data_dir)
    blocklist_mgr = BlocklistManager(data_dir, config_mgr)
    dns_engine = DNSEngine(config_mgr, blocklist_mgr)
    web_server = WebServer(config_mgr, blocklist_mgr, dns_engine, static_dir)

    # 5. Start DNS Engine
    try:
        dns_engine.start()
    except Exception as e:
        print(f"\n[FATAL] Gagal memulai DNS Server:\n{e}\n")
        print("Solusi: Jalankan aplikasi dengan klik kanan -> 'Run as Administrator',")
        print("atau pastikan tidak ada layanan lain yang memakai port 53 (seperti Internet Connection Sharing).\n")
        time.sleep(5)
        sys.exit(1)

    # 6. Start Web Dashboard
    web_server.start()

    lan_ips = get_lan_ips()
    primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"
    web_port = config_mgr.get("web_port", 5380)

    # Otomatis buka jendela desktop native mandiri (tanpa tab/address bar browser)
    try:
        from windows_utils import launch_native_window
        threading.Timer(0.8, lambda: launch_native_window(f"http://localhost:{web_port}")).start()
    except Exception as e:
        print(f"[Main] Warning launch window: {e}")

    print("\n" + "-" * 60)
    print(f"🚀 DNS Server AKTIF di port 53 (UDP & TCP)")
    print(f"🛡️ Dashboard Native: http://localhost:{web_port}")
    print(f"📱 Akses dari HP/Laptop lain di LAN: http://{primary_ip}:{web_port}")
    print(f"📍 IP DNS untuk Router/HP: {primary_ip}")
    print("-" * 60 + "\n")

    # Shutdown handler
    is_shutting_down = False
    def shutdown():
        nonlocal is_shutting_down
        if is_shutting_down:
            return
        is_shutting_down = True
        print("\n[Main] Menghentikan AdShield DNS...")
        dns_engine.stop()
        dns_engine.db.close()
        web_server.stop()
        allow_sleep()
        print("[Main] Selesai. Selamat tinggal!")
        os._exit(0)

    # Register signals
    signal.signal(signal.SIGINT, lambda s, f: shutdown())
    signal.signal(signal.SIGTERM, lambda s, f: shutdown())

    # 7. Start System Tray (or keep main thread alive if --no-tray)
    if not args.no_tray:
        try:
            tray = TrayApp(config_mgr, blocklist_mgr, dns_engine, on_exit_callback=shutdown)
            tray.run()
        except Exception as e:
            print(f"[Main] Peringatan: System tray gagal dijalankan ({e}). Beralih ke mode konsol.")
            while not is_shutting_down:
                time.sleep(1)
    else:
        print("[Main] Berjalan di background (--no-tray). Tekan Ctrl+C untuk berhenti.")
        while not is_shutting_down:
            time.sleep(1)

if __name__ == "__main__":
    main()
