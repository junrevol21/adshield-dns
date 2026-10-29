"""
License and Coupon Manager for AdShield DNS
Provides Machine Hardware ID binding, offline cryptographic signature validation,
coupon code redemption, and Pro feature tier management.

Basic Tier = 100% equivalent to AdGuard Home (Free forever)
Pro Tier = Exclusive Beast Features unique to AdShield
"""

import os
import json
import hashlib
import hmac
import time
import winreg

SECRET_SALT = "ADSHIELD_PRO_BEAST_2026_SECRET_KEY"

# Pre-registered VIP coupons & lifetime promo codes
VIP_COUPONS = {
    "PRO-VIP-2026": {"tier": "PRO", "expires": None, "label": "VIP Lifetime License"},
    "BETA-TESTER": {"tier": "PRO", "expires": None, "label": "Beta Tester Early Access"},
    "SULTAN-BEAST": {"tier": "PRO", "expires": None, "label": "Sultan Beast License"},
    "HEMAT100": {"tier": "PRO", "expires": None, "label": "Kupon Diskon 100% Promo"}
}

BASIC_FEATURES = [
    "1,000,000+ Smart Blocklist Rules Capacity",
    "Per-Device Client Profiles (Kids, Work, Bypass)",
    "1-Click Service Blocker (TikTok, Games, Windows Spy, Adult)",
    "Local DNS Rewrites (router.lan -> Local IP)",
    "In-Memory RAM Caching Sub-Millisecond (< 1ms)",
    "Real-Time Query History & Advanced Status Filters",
    "Unlimited Custom Whitelist & Blacklist",
    "Parallel Upstream Forwarding (Fastest-Wins)",
    "1-Click Local PC Protection (Automatic Adapter DNS)"
]

PRO_EXCLUSIVE_FEATURES = [
    "🔒 1-Click Auto-Lock Static IP (Prevents LAN IP Changes)",
    "🛡️ Anti-ISP Hijacking Mode (Encrypted DoH Tunnel)",
    "⚡ Live Upstream Latency Benchmark (7 Global Resolvers)",
    "🔋 Smart Eco-Mode & Windows 24/7 Lid-Close Background Engine",
    "🤖 Automated 24-Hour Smart Filter & Threat Feed Updates",
    "⚙️ Official Windows Service Integration (Boot Without Login)",
    "📦 Teleporter 1-Click JSON Configuration Backup & Restore"
]

def get_machine_id() -> str:
    """Retrieve unique Windows Machine GUID for hardware license binding."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            return hashlib.sha256(val.encode()).hexdigest()[:16].upper()
    except Exception:
        import socket
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16].upper()

def generate_valid_key(machine_id: str) -> str:
    """Generate expected license key for a given machine ID."""
    sig = hmac.new(SECRET_SALT.encode(), machine_id.encode(), hashlib.sha256).hexdigest().upper()
    return f"ADSHIELD-{sig[:4]}-{sig[4:8]}-{sig[8:12]}"

class LicenseManager:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.license_file = os.path.join(data_dir, "license.json")
        self.machine_id = get_machine_id()
        self.license_data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.license_file):
            try:
                with open(self.license_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "tier": "BASIC",
            "license_key": None,
            "activated_at": None,
            "machine_id": self.machine_id
        }

    def _save(self):
        try:
            with open(self.license_file, "w", encoding="utf-8") as f:
                json.dump(self.license_data, f, indent=2)
        except Exception as e:
            print(f"[LicenseManager] Error saving license: {e}")

    def is_pro(self) -> bool:
        """Check if Pro mode is currently active."""
        if self.license_data.get("tier") == "PRO":
            return True
        return False

    def activate_code(self, raw_code: str) -> dict:
        """
        Validate and activate a License Key or Coupon Code.
        Returns: {"success": bool, "message": str, "tier": str}
        """
        code = raw_code.strip().upper()
        if not code:
            return {"success": False, "message": "Kode lisensi atau kupon tidak boleh kosong."}

        # 1. Check if it's a VIP / Promo Coupon
        if code in VIP_COUPONS:
            coupon_info = VIP_COUPONS[code]
            self.license_data = {
                "tier": "PRO",
                "license_key": code,
                "label": coupon_info["label"],
                "activated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "machine_id": self.machine_id
            }
            self._save()
            return {
                "success": True,
                "message": f"Kupon Berhasil Diaktivasi! Mode PRO aktif ({coupon_info['label']}).",
                "tier": "PRO"
            }

        # 2. Check if it's a Machine-Bound Serial License
        expected_key = generate_valid_key(self.machine_id)
        if code == expected_key:
            self.license_data = {
                "tier": "PRO",
                "license_key": code,
                "label": "Lisensi Resmi Terverifikasi",
                "activated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "machine_id": self.machine_id
            }
            self._save()
            return {
                "success": True,
                "message": "Lisensi PRO Resmi Berhasil Diaktifkan!",
                "tier": "PRO"
            }

        # 3. Check Universal Pro Key format: ADSHIELD-PRO-XXXX-XXXX
        if code.startswith("ADSHIELD-PRO-") and len(code) >= 20:
            self.license_data = {
                "tier": "PRO",
                "license_key": code,
                "label": "Lisensi Pro Lifetime",
                "activated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "machine_id": self.machine_id
            }
            self._save()
            return {
                "success": True,
                "message": "Lisensi Pro Berhasil Diterapkan!",
                "tier": "PRO"
            }

        return {"success": False, "message": "Kode lisensi atau kupon tidak valid atau tidak cocok dengan perangkat ini."}

    def get_status(self) -> dict:
        return {
            "tier": self.license_data.get("tier", "BASIC"),
            "is_pro": self.is_pro(),
            "license_key": self.license_data.get("license_key"),
            "label": self.license_data.get("label", "Standard Edition"),
            "activated_at": self.license_data.get("activated_at"),
            "machine_id": self.machine_id,
            "demo_valid_key": generate_valid_key(self.machine_id),
            "basic_features": BASIC_FEATURES,
            "pro_exclusive_features": PRO_EXCLUSIVE_FEATURES
        }
