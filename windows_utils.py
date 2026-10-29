"""
Windows System Utilities for AdShield DNS
- Sleep prevention (Away mode / System required)
- Auto-start with Windows (Run registry key)
- Local LAN IP detection
- Administrator privilege verification
"""

import sys
import os
import socket
import ctypes
import winreg
import subprocess

# Windows Execution States
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_AWAYMODE_REQUIRED = 0x00000040

REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "AdShieldDNS"

def is_admin() -> bool:
    """Check if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def prevent_sleep():
    """Prevent Windows from entering sleep or standby mode while DNS server is running."""
    try:
        # ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
        flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
        res = ctypes.windll.kernel32.SetThreadExecutionState(flags)
        if res == 0:
            # Fallback without awaymode
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to set execution state: {e}")
        return False

def allow_sleep():
    """Restore normal Windows sleep behavior."""
    try:
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        return True
    except Exception:
        return False

def is_autostart_enabled() -> bool:
    """Check if app is configured to auto-start on Windows login."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_REG_NAME)
            return bool(val)
    except FileNotFoundError:
        return False
    except Exception:
        return False

def set_autostart(enable: bool) -> bool:
    """Enable or disable auto-start on Windows login."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                # Use current executable path
                if getattr(sys, 'frozen', False):
                    exe_path = f'"{sys.executable}"'
                else:
                    # When running from python source
                    exe_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'
                winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, exe_path)
            else:
                try:
                    winreg.DeleteValue(key, APP_REG_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to set autostart: {e}")
        return False

def get_lan_ips() -> list:
    """Get active local network IPv4 addresses."""
    ips = []
    # Primary IP by test routing to public IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and not primary.startswith("127."):
            ips.append(primary)
    except Exception:
        pass

    # All adapter IPs
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips or ["127.0.0.1"]

def run_silent_cmd(cmd: str) -> str:
    """Run a shell command silently on Windows with absolutely NO console window popup."""
    startupinfo = None
    creationflags = 0
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= (subprocess.STARTF_USESHOWWINDOW | subprocess.STARTF_USESTDHANDLES)
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    try:
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            errors="ignore",
            startupinfo=startupinfo,
            creationflags=creationflags
        )
        return res.stdout or ""
    except Exception as e:
        print(f"[WindowsUtils] Error running silent cmd: {e}")
        return ""

# Adapter status cache to prevent unnecessary netsh polling
_adapter_cache = {
    "name": "Wi-Fi",
    "is_local": False,
    "last_checked": 0
}

def get_active_adapter_name() -> str:
    """Get the name of the active, connected network interface (e.g. 'Wi-Fi' or 'Ethernet')."""
    import time
    now = time.time()
    if now - _adapter_cache["last_checked"] < 10 and _adapter_cache["name"]:
        return _adapter_cache["name"]

    out = run_silent_cmd("netsh interface show interface")
    for line in out.splitlines():
        line = line.strip()
        if "Connected" in line:
            parts = line.split()
            if len(parts) >= 4:
                name = " ".join(parts[3:])
                if "Tailscale" not in name and "Loopback" not in name:
                    _adapter_cache["name"] = name
                    return name
    return _adapter_cache.get("name") or "Wi-Fi"

def is_local_dns_applied(adapter_name: str = None) -> bool:
    """Check if the adapter's DNS is currently configured to AdShield DNS."""
    import time
    now = time.time()
    if not adapter_name:
        adapter_name = get_active_adapter_name()

    if now - _adapter_cache["last_checked"] < 10:
        return _adapter_cache["is_local"]

    out = run_silent_cmd(f'netsh interface ip show dns name="{adapter_name}"')
    lan_ips = get_lan_ips()
    is_applied = False
    for ip in ["127.0.0.1"] + lan_ips:
        if ip in out:
            is_applied = True
            break

    _adapter_cache["is_local"] = is_applied
    _adapter_cache["last_checked"] = now
    return is_applied

def apply_local_dns(adapter_name: str = None) -> bool:
    """Apply AdShield DNS to the local Windows network adapter."""
    if not adapter_name:
        adapter_name = get_active_adapter_name()
    lan_ips = get_lan_ips()
    primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"
    try:
        # Set primary DNS
        run_silent_cmd(f'netsh interface ip set dns name="{adapter_name}" static {primary_ip}')
        # Add secondary fallback (Cloudflare)
        run_silent_cmd(f'netsh interface ip add dns name="{adapter_name}" 1.1.1.1 index=2')
        # Flush Windows DNS Cache
        run_silent_cmd('ipconfig /flushdns')
        # Invalidate cache
        _adapter_cache["is_local"] = True
        _adapter_cache["last_checked"] = 0
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to apply local DNS: {e}")
        return False

def reset_local_dns(adapter_name: str = None) -> bool:
    """Reset the adapter's DNS back to automatic (DHCP)."""
    if not adapter_name:
        adapter_name = get_active_adapter_name()
    try:
        run_silent_cmd(f'netsh interface ip set dns name="{adapter_name}" dhcp')
        # Flush Windows DNS Cache
        run_silent_cmd('ipconfig /flushdns')
        # Invalidate cache
        _adapter_cache["is_local"] = False
        _adapter_cache["last_checked"] = 0
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to reset local DNS: {e}")
        return False

# Top MAC Vendor OUIs for automatic device recognition on LAN
MAC_VENDORS = {
    # Apple
    "00:17:f2": "Apple (iPhone/Mac)", "28:cf:e9": "Apple (iPhone/Mac)", "3c:07:54": "Apple (iPhone/Mac)",
    "44:4c:0c": "Apple (iPhone/Mac)", "a4:83:e7": "Apple (iPhone/Mac)", "f0:18:98": "Apple (iPhone/Mac)",
    "ac:bc:32": "Apple (iPhone/Mac)", "bc:d0:74": "Apple (iPhone/Mac)", "dc:a9:04": "Apple (iPhone/Mac)",
    # Samsung
    "00:07:ab": "Samsung Galaxy", "00:12:fb": "Samsung Galaxy", "14:49:e0": "Samsung Galaxy",
    "40:0e:85": "Samsung Galaxy", "50:01:d9": "Samsung Galaxy", "78:47:1d": "Samsung Galaxy",
    "94:65:2d": "Samsung Galaxy", "b4:0b:44": "Samsung Galaxy", "c8:14:51": "Samsung Galaxy",
    # Xiaomi
    "00:9e:c8": "Xiaomi / Redmi", "18:59:36": "Xiaomi / Redmi", "34:80:b3": "Xiaomi / Redmi",
    "74:51:ba": "Xiaomi / Redmi", "8c:be:be": "Xiaomi / Redmi", "f8:a4:5f": "Xiaomi / Redmi",
    # LG & Sony
    "00:1c:62": "LG Smart TV", "10:f9:6f": "LG Smart TV", "20:3d:b2": "LG Smart TV",
    "00:01:4a": "Sony TV / PlayStation", "70:9e:29": "Sony TV / PlayStation",
    # Routers
    "c8:c4:65": "Router ZTE (IndiHome)", "7c:a1:ae": "Perangkat Wi-Fi HP",
    "00:46:4b": "Router Huawei", "70:72:cf": "Router Huawei"
}

def get_device_discovery() -> list:
    """Discover devices on local network using Windows ARP table and MAC vendor lookup."""
    devices = []
    out = run_silent_cmd("arp -a")
    for line in out.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) >= 3 and parts[1].count("-") == 5:
            ip = parts[0]
            mac = parts[1].lower().replace("-", ":")
            if ip.startswith("127.") or ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                continue
            oui = mac[:8]
            vendor = MAC_VENDORS.get(oui, "Perangkat Wi-Fi (Umum)")
            if ip.endswith(".1"):
                vendor = "Router / Gateway Utama"
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor
            })
    return devices

def is_windows_service_installed() -> bool:
    """Check if AdShieldDNS is registered as a Windows Service."""
    out = run_silent_cmd("sc query AdShieldDNS")
    return "SERVICE_NAME: AdShieldDNS" in out

def install_windows_service() -> bool:
    """Register AdShield as an official auto-starting background Windows Service."""
    if getattr(sys, 'frozen', False):
        exe_path = f'"{sys.executable}" --no-tray'
    else:
        exe_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --no-tray'
    cmd = f'sc create AdShieldDNS binPath= "{exe_path}" start= auto DisplayName= "AdShield DNS Service"'
    out = run_silent_cmd(cmd)
    run_silent_cmd("sc start AdShieldDNS")
    return "SUCCESS" in out or "exists" in out.lower()

def uninstall_windows_service() -> bool:
    """Unregister the AdShield Windows Service."""
    run_silent_cmd("sc stop AdShieldDNS")
    out = run_silent_cmd("sc delete AdShieldDNS")
    return "SUCCESS" in out

class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ('ACLineStatus', ctypes.c_byte),
        ('BatteryFlag', ctypes.c_byte),
        ('BatteryLifePercent', ctypes.c_byte),
        ('SystemStatusFlag', ctypes.c_byte),
        ('BatteryLifeTime', ctypes.c_ulong),
        ('BatteryFullLifeTime', ctypes.c_ulong),
    ]

def get_power_status() -> dict:
    """Detect AC power line vs battery status to support Eco-Mode for laptop 24/7 run."""
    try:
        status = SYSTEM_POWER_STATUS()
        if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            ac_online = status.ACLineStatus == 1
            battery_pct = status.BatteryLifePercent if status.BatteryLifePercent <= 100 else None
            return {
                "ac_online": ac_online,
                "battery_percent": battery_pct,
                "power_mode": "AC Power (High Performance)" if ac_online else f"Battery ({battery_pct}%)",
                "power_mode_id": "AC Listrik (Performa Maksimal)" if ac_online else f"Baterai Laptop ({battery_pct}%)",
                "eco_mode": not ac_online
            }
    except Exception:
        pass
    return {
        "ac_online": True,
        "battery_percent": 100,
        "power_mode": "AC Power (High Performance)",
        "power_mode_id": "AC Listrik (Performa Maksimal)",
        "eco_mode": False
    }

def open_lid_power_settings() -> bool:
    """Open Windows Power Options so user can set 'When I close the lid: Do nothing'."""
    try:
        subprocess.Popen("control.exe /name Microsoft.PowerOptions", shell=True)
        return True
    except Exception:
        return False

def get_adapter_ip_info(adapter_name: str = None) -> dict:
    """Detect current IPv4 address, subnet mask, default gateway, and DHCP status of active adapter."""
    if not adapter_name:
        adapter_name = get_active_adapter_name()
    out = run_silent_cmd(f'netsh interface ip show config name="{adapter_name}"')
    ip = None
    mask = "255.255.255.0"
    gateway = None
    dhcp_enabled = True

    for line in out.splitlines():
        line = line.strip()
        if "DHCP enabled" in line:
            dhcp_enabled = "yes" in line.lower()
        elif "IP Address" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                ip = parts[1].strip()
        elif "mask" in line:
            m_parts = line.split("mask")
            if len(m_parts) >= 2:
                mask = m_parts[1].replace(")", "").strip()
        elif "Default Gateway" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                gw = parts[1].strip()
                if gw and not gw.startswith("0."):
                    gateway = gw

    if not ip:
        lan_ips = get_lan_ips()
        ip = lan_ips[0] if lan_ips else "192.168.100.168"
    if not gateway and ip:
        gw_parts = ip.split(".")
        gateway = f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.1"

    is_locked = not dhcp_enabled

    return {
        "adapter_name": adapter_name,
        "ip": ip,
        "mask": mask,
        "gateway": gateway,
        "dhcp_enabled": dhcp_enabled,
        "is_locked": is_locked
    }

def lock_adapter_ip(adapter_name: str = None) -> bool:
    """Lock current adapter IP as Static so router and devices never lose connection."""
    info = get_adapter_ip_info(adapter_name)
    adapter = info["adapter_name"]
    ip = info["ip"]
    mask = info["mask"]
    gateway = info["gateway"]
    if not ip or not gateway:
        return False
    try:
        cmd = f'netsh interface ip set address name="{adapter}" static {ip} {mask} {gateway}'
        run_silent_cmd(cmd)
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to lock static IP: {e}")
        return False

def unlock_adapter_ip(adapter_name: str = None) -> bool:
    """Unlock adapter IP back to automatic DHCP."""
    if not adapter_name:
        adapter_name = get_active_adapter_name()
    try:
        cmd = f'netsh interface ip set address name="{adapter_name}" dhcp'
        run_silent_cmd(cmd)
        return True
    except Exception as e:
        print(f"[WindowsUtils] Failed to unlock IP: {e}")
        return False

def launch_native_window(url: str) -> bool:
    """
    Launch a clean standalone desktop native application window (PWA/App mode)
    without browser tabs, URL address bars, or browser extensions.
    """
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ]
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    ]

    app_args = [
        f'--app={url}',
        '--window-size=1280,860',
        '--disable-features=Translate',
        '--disable-extensions'
    ]

    for p in edge_paths + chrome_paths:
        if os.path.exists(p):
            try:
                subprocess.Popen([p] + app_args)
                return True
            except Exception:
                pass

    # Fallback to default browser
    import webbrowser
    webbrowser.open(url)
    return False



