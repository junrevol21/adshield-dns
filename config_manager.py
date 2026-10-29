"""
Configuration Manager for AdShield DNS
"""

import os
import json
import time

DEFAULT_CONFIG = {
    "adblock_enabled": True,
    "pause_until": 0,
    "upstream_provider": "Cloudflare",
    "upstream_dns": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"],
    "upstream_mode": "race", # "race" (Parallel fastest-wins) or "serial"
    "doh_enabled": True,
    "doh_only": False, # When True, bypasses all plain UDP port 53 to prevent ISP hijack
    "blocking_mode": "0.0.0.0",
    "dns_port": 53,
    "web_port": 5380,
    "cache_enabled": True,
    "cache_ttl_min": 60,
    "cache_ttl_max": 86400,
    "optimistic_cache": True, # Serve stale cache if upstream times out/fails
    "eco_mode": True, # Low-power background mode for laptops
    "services_blocked": {
        "windows_spy": True,
        "tiktok": False,
        "meta_trackers": False,
        "online_games": False,
        "crypto_mining": True,
        "safesearch": False,
        "gambling_adult": False,
        "ai_trackers": False
    },
    "dns_rewrites": [
        {"domain": "modem.lan", "ip": "192.168.100.1"},
        {"domain": "router.lan", "ip": "192.168.100.1"}
    ],
    "rate_limit_enabled": True,
    "rate_limit_rps": 100,
    "auto_update_enabled": True,
    "auto_update_interval_hours": 24,
    "clients": [
        # Per-client custom rules (Beda aturan tiap HP / TV)
        # {"ip": "192.168.100.55", "name": "HP Anak", "profile": "kids", "safesearch": True, "blocked_services": ["tiktok", "online_games", "gambling_adult"]}
    ],
    "blocklist_sources": [
        {
            "id": "stevenblack",
            "name": "StevenBlack Unified Hosts",
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "enabled": True,
            "count": 75950,
            "last_updated": "Preloaded"
        },
        {
            "id": "adaway",
            "name": "AdAway Default Blocklist",
            "url": "https://adaway.org/hosts.txt",
            "enabled": True,
            "count": 21,
            "last_updated": "Preloaded"
        },
        {
            "id": "hagezi",
            "name": "Hagezi Multi PRO (250.000+ Rules)",
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
            "enabled": False,
            "count": 0,
            "last_updated": "-"
        },
        {
            "id": "oisd",
            "name": "OISD Big List (300.000+ Rules)",
            "url": "https://big.oisd.nl/",
            "enabled": False,
            "count": 0,
            "last_updated": "-"
        },
        {
            "id": "adguard_base",
            "name": "AdGuard Official DNS Filter",
            "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            "enabled": False,
            "count": 0,
            "last_updated": "-"
        }
    ]
}

UPSTREAM_PRESETS = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "AdGuard": ["94.140.14.14", "94.140.15.15"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"]
}

class ConfigManager:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.config_path = os.path.join(data_dir, "config.json")
        self.config = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cfg = DEFAULT_CONFIG.copy()
                    cfg.update(data)
                    return cfg
            except Exception as e:
                print(f"[ConfigManager] Error reading config: {e}. Using defaults.")
        return DEFAULT_CONFIG.copy()

    def save(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"[ConfigManager] Error saving config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save()

    def is_blocking_active(self) -> bool:
        """Return True if adblocking is enabled and not currently paused."""
        if not self.config.get("adblock_enabled", True):
            return False
        pause_until = self.config.get("pause_until", 0)
        if pause_until > 0:
            if time.time() < pause_until:
                return False
            else:
                self.config["pause_until"] = 0
                self.save()
        return True

    def pause_blocking(self, seconds: int):
        """Pause blocking for specified seconds. If seconds <= 0, pause indefinitely."""
        if seconds > 0:
            self.config["pause_until"] = time.time() + seconds
        else:
            self.config["adblock_enabled"] = False
            self.config["pause_until"] = 0
        self.save()

    def resume_blocking(self):
        """Resume blocking immediately."""
        self.config["adblock_enabled"] = True
        self.config["pause_until"] = 0
        self.save()

    def set_upstream(self, provider: str, custom_servers: list = None):
        """Set upstream DNS provider."""
        self.config["upstream_provider"] = provider
        if provider in UPSTREAM_PRESETS:
            self.config["upstream_dns"] = UPSTREAM_PRESETS[provider]
        elif custom_servers:
            self.config["upstream_dns"] = custom_servers
        self.save()

    def get_client_config(self, client_ip: str) -> dict:
        """Find configured client profile for a specific client IP."""
        for client in self.config.get("clients", []):
            if client.get("ip") == client_ip:
                return client
        return {"ip": client_ip, "name": client_ip, "profile": "standard"}
