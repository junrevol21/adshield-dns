"""
PyInstaller Build Script for AdShield DNS
Produces a single standalone AdShield-DNS.exe with system tray and embedded web dashboard.
"""

import os
import sys
import subprocess
import shutil

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def build():
    print("=== Memulai Kompilasi AdShield DNS ke .exe ===")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    build_dir = os.path.join(base_dir, "build")

    icon_path = os.path.join(base_dir, "data", "icon.ico")
    static_dir = os.path.join(base_dir, "static")
    default_list = os.path.join(base_dir, "data", "default_blocklist.txt")
    icon_png = os.path.join(base_dir, "data", "icon.png")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=AdShield-DNS",
        "--onefile",
        "--noconsole",
        "--uac-admin",
        f"--icon={icon_path}",
        f"--add-data={static_dir};static",
        f"--add-data={default_list};data",
        f"--add-data={icon_png};data",
        f"--add-data={icon_path};data",
        "--hidden-import=dns",
        "--hidden-import=dns.message",
        "--hidden-import=dns.query",
        "--hidden-import=dns.rdatatype",
        "--hidden-import=dns.rrset",
        "--hidden-import=dns.rcode",
        "--hidden-import=bottle",
        "--hidden-import=sqlite3",
        "--hidden-import=license_manager",
        "--hidden-import=pystray",
        "--hidden-import=PIL",
        "--clean",
        os.path.join(base_dir, "main.py")
    ]

    print("Executing command:")
    print(" ".join(cmd))
    res = subprocess.run(cmd, cwd=base_dir)

    if res.returncode == 0:
        exe_file = os.path.join(dist_dir, "AdShield-DNS.exe")
        print("\n" + "=" * 60)
        print(f"🎉 SUKSES! File executable berhasil dibuat:")
        print(f"📂 Lokasi: {exe_file}")
        if os.path.exists(exe_file):
            size_mb = os.path.getsize(exe_file) / (1024 * 1024)
            print(f"📊 Ukuran: {size_mb:.2f} MB")
        print("=" * 60)
    else:
        print("\n❌ Gagal melakukan kompilasi PyInstaller.")

if __name__ == "__main__":
    build()
