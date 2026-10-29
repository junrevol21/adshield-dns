"""
Blocklist Manager for AdShield DNS
- Manages preloaded and online blocklists (StevenBlack, AdAway, etc.)
- Manages Custom Whitelist and Custom Blacklist
- Ultra-fast subdomain hierarchy matching
"""

import os
import re
import time
import urllib.request
import threading
from typing import Set, Tuple, List, Dict

# Catalog of pre-configured specific services to block on demand
SERVICE_CATALOG = {
    "windows_spy": {
        "name": "Anti-Telemetri Windows 10/11",
        "domains": {
            "vortex.data.microsoft.com", "vortex-win.data.microsoft.com", "telemetry.microsoft.com",
            "telemetry.urs.microsoft.com", "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
            "diagnostics.support.microsoft.com", "feedback.windows.com", "activity.windows.com",
            "insider.windows.com", "fe3.delivery.mp.microsoft.com", "survey.watson.microsoft.com"
        }
    },
    "tiktok": {
        "name": "TikTok & ByteDance",
        "domains": {
            "tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com",
            "muscdn.com", "musical.ly", "snssdk.com", "pstatp.com", "bytedance.com"
        }
    },
    "meta_trackers": {
        "name": "Meta / Facebook / Instagram Trackers",
        "domains": {
            "graph.facebook.com", "connect.facebook.net", "pixel.facebook.com", "analytics.facebook.com",
            "ads.facebook.com", "an.facebook.com", "instagram.c10r.facebook.com"
        }
    },
    "online_games": {
        "name": "Game Online Anak (Roblox, FreeFire, Steam, dll)",
        "domains": {
            "roblox.com", "rbxcdn.com", "roblox.cn", "freefiremobile.com", "garena.com",
            "mobilelegends.com", "moonton.com", "steampowered.com", "steamcommunity.com",
            "riotgames.com", "epicgames.com", "pubgmobile.com"
        }
    },
    "crypto_mining": {
        "name": "Anti-Cryptojacking & Miner",
        "domains": {
            "coinhive.com", "coin-hive.com", "crypto-loot.com", "cryptoloot.pro",
            "monerominer.rocks", "webminerpool.com", "miner.pr0gramm.com", "authedmine.com"
        }
    },
    "gambling_adult": {
        "name": "Judi Online & Pornografi (Indo Safe)",
        "domains": {
            "pornhub.com", "xvideos.com", "xnxx.com", "onlyfans.com", "chaturbate.com", "redtube.com", "youporn.com",
            "sbobet.com", "pragmaticplay.com", "pgsoft.com", "slot88.com", "maxbet.com", "agen138.com", "judol.com"
        }
    },
    "ai_trackers": {
        "name": "AI Telemetry & Web Scrapers",
        "domains": {
            "telemetry.openai.com", "api.statsig.com", "browser-intake-datadoghq.com"
        }
    }
}

class BlocklistManager:
    def __init__(self, data_dir: str, config_mgr):
        self.data_dir = data_dir
        self.config_mgr = config_mgr
        self.lock = threading.RLock()

        self.whitelist_file = os.path.join(data_dir, "whitelist.txt")
        self.blacklist_file = os.path.join(data_dir, "blacklist.txt")
        self.default_blocklist_file = os.path.join(data_dir, "default_blocklist.txt")

        # In-memory sets
        self.blocked_domains: Set[str] = set()
        self.custom_blacklist: Set[str] = set()
        self.custom_whitelist: Set[str] = set()

        self.is_updating = False
        self.last_update_status = "Ready"

        # Initialize files if missing
        self._init_files()
        # Initial load
        self.reload_all()

        # Start periodic auto-updater thread (runs every 24 hours to keep blocklist smart)
        self.auto_update_thread = threading.Thread(target=self._auto_update_scheduler, name="Blocklist-AutoUpdater", daemon=True)
        self.auto_update_thread.start()

    def _auto_update_scheduler(self):
        """Check and auto-update blocklists every 24 hours in the background."""
        while True:
            # Sleep in 60-second chunks
            for _ in range(24 * 60):
                time.sleep(60)
            if self.config_mgr.get("auto_update_enabled", True):
                print("[BlocklistManager] Menjalankan pembaruan otomatis blocklist 24 jam...")
                self.update_blocklists_async()

    def _init_files(self):
        if not os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, "w", encoding="utf-8") as f:
                f.write("# AdShield DNS Custom Whitelist\n# Masukkan domain yang tidak ingin diblokir (satu per baris)\n")
        if not os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, "w", encoding="utf-8") as f:
                f.write("# AdShield DNS Custom Blacklist\n# Masukkan domain kustom yang ingin diblokir (satu per baris)\n")

    def reload_all(self):
        """Reload all lists into memory."""
        with self.lock:
            # 1. Load custom whitelist
            self.custom_whitelist = self._read_domain_file(self.whitelist_file)

            # 2. Load custom blacklist
            self.custom_blacklist = self._read_domain_file(self.blacklist_file)

            # 3. Load blocklist sources
            domains = set()

            # Load default base blocklist if available
            if os.path.exists(self.default_blocklist_file):
                base_domains = self._read_domain_file(self.default_blocklist_file)
                domains.update(base_domains)

            # Load cached sources
            sources = self.config_mgr.get("blocklist_sources", [])
            for src in sources:
                if src.get("enabled", True):
                    cache_file = os.path.join(self.data_dir, f"cache_{src.get('id')}.txt")
                    if os.path.exists(cache_file):
                        src_domains = self._read_domain_file(cache_file)
                        domains.update(src_domains)

            self.blocked_domains = domains
            import gc
            gc.collect()
            print(f"[BlocklistManager] Loaded {len(self.blocked_domains)} blocklist rules, "
                  f"{len(self.custom_whitelist)} whitelisted, {len(self.custom_blacklist)} blacklisted.")

    def _read_domain_file(self, filepath: str) -> Set[str]:
        domains = set()
        if not os.path.exists(filepath):
            return domains
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    
                    # Support Adblock-style rules: ||example.com^
                    if line.startswith("||"):
                        clean_d = line[2:].split("^")[0].split("$")[0].strip().lower().rstrip(".")
                        if clean_d and "." in clean_d:
                            domains.add(clean_d)
                        continue
                    elif line.startswith("@@||"):
                        # Whitelist rule in adblock syntax
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        d = parts[1].lower().rstrip(".")
                        if ip in ("0.0.0.0", "127.0.0.1") and d not in ("localhost", "local", "broadcasthost", "0.0.0.0"):
                            domains.add(d)
                    elif len(parts) == 1 and "." in parts[0]:
                        domains.add(parts[0].lower().rstrip("."))
        except Exception as e:
            print(f"[BlocklistManager] Error reading {filepath}: {e}")
        return domains

    def get_dns_rewrite(self, domain: str):
        """Check if domain has a custom local DNS rewrite rule."""
        domain = domain.lower().rstrip(".")
        rewrites = self.config_mgr.get("dns_rewrites", [])
        for rw in rewrites:
            rw_d = rw.get("domain", "").lower().rstrip(".")
            if rw_d == domain:
                return rw.get("ip")
        return None

    def is_blocked(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain is blocked.
        Returns (is_blocked: bool, reason: str).
        Performs O(k) suffix matching where k = number of domain parts.
        """
        domain = domain.lower().rstrip(".")
        if not domain:
            return False, "empty"

        parts = domain.split(".")

        # Generate hierarchy: ["ads.example.com", "example.com"]
        candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]

        with self.lock:
            # 1. Check custom whitelist first
            for cand in candidates:
                if cand in self.custom_whitelist:
                    return False, "whitelisted"

            # 2. Check custom blacklist
            for cand in candidates:
                if cand in self.custom_blacklist:
                    return True, "custom_blacklist"

            # 3. Check Quick Service Catalog (TikTok, Windows Spy, Meta, Games, Crypto)
            services_cfg = self.config_mgr.get("services_blocked", {})
            for s_id, s_info in SERVICE_CATALOG.items():
                if services_cfg.get(s_id, False):
                    for cand in candidates:
                        if cand in s_info["domains"]:
                            return True, f"service:{s_id}"

            # 4. Check loaded blocklists
            for cand in candidates:
                if cand in self.blocked_domains:
                    return True, "blocklist"

        return False, "allowed"

    def is_blocked_for_client(self, domain: str, client_cfg: dict) -> Tuple[bool, str]:
        """
        Check if domain is blocked with per-client policies (Kids, Bypass, Custom).
        """
        profile = client_cfg.get("profile", "standard")
        if profile == "bypass":
            return False, "bypass"

        domain = domain.lower().rstrip(".")
        if not domain:
            return False, "empty"

        parts = domain.split(".")
        candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]

        with self.lock:
            # 1. Custom Whitelist (always permitted)
            for cand in candidates:
                if cand in self.custom_whitelist:
                    return False, "whitelisted"

            # 2. Custom Blacklist (always blocked)
            for cand in candidates:
                if cand in self.custom_blacklist:
                    return True, "custom_blacklist"

            # 3. Client Profile checks
            if profile == "kids":
                # Always block adult/gambling, games, and tiktok for kids
                kids_blocked = ["gambling_adult", "online_games", "tiktok"]
                for s_id in kids_blocked:
                    if s_id in SERVICE_CATALOG:
                        for cand in candidates:
                            if cand in SERVICE_CATALOG[s_id]["domains"]:
                                return True, f"kids_protection:{s_id}"

            # 4. Specific Per-Client Blocked Services
            client_services = client_cfg.get("blocked_services", [])
            for s_id in client_services:
                if s_id in SERVICE_CATALOG:
                    for cand in candidates:
                        if cand in SERVICE_CATALOG[s_id]["domains"]:
                            return True, f"client_service:{s_id}"

            # 5. Global Blocked Services from config
            services_cfg = self.config_mgr.get("services_blocked", {})
            for s_id, s_info in SERVICE_CATALOG.items():
                if services_cfg.get(s_id, False):
                    for cand in candidates:
                        if cand in s_info["domains"]:
                            return True, f"service:{s_id}"

            # 6. Global Blocked Domains
            for cand in candidates:
                if cand in self.blocked_domains:
                    return True, "blocklist"

        return False, "allowed"

    def add_to_whitelist(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        if not domain or "." not in domain:
            return False
        with self.lock:
            self.custom_whitelist.add(domain)
            # Remove from custom blacklist if present
            self.custom_blacklist.discard(domain)
            self._save_set_to_file(self.whitelist_file, self.custom_whitelist, "Custom Whitelist")
            self._save_set_to_file(self.blacklist_file, self.custom_blacklist, "Custom Blacklist")
        return True

    def remove_from_whitelist(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain in self.custom_whitelist:
                self.custom_whitelist.remove(domain)
                self._save_set_to_file(self.whitelist_file, self.custom_whitelist, "Custom Whitelist")
                return True
        return False

    def add_to_blacklist(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        if not domain or "." not in domain:
            return False
        with self.lock:
            self.custom_blacklist.add(domain)
            self.custom_whitelist.discard(domain)
            self._save_set_to_file(self.blacklist_file, self.custom_blacklist, "Custom Blacklist")
            self._save_set_to_file(self.whitelist_file, self.custom_whitelist, "Custom Whitelist")
        return True

    def remove_from_blacklist(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain in self.custom_blacklist:
                self.custom_blacklist.remove(domain)
                self._save_set_to_file(self.blacklist_file, self.custom_blacklist, "Custom Blacklist")
                return True
        return False

    def _save_set_to_file(self, filepath: str, domain_set: Set[str], header: str):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# AdShield DNS - {header}\n# Total: {len(domain_set)}\n\n")
                for d in sorted(domain_set):
                    f.write(f"{d}\n")
        except Exception as e:
            print(f"[BlocklistManager] Error writing to {filepath}: {e}")

    def update_blocklists_async(self, callback=None):
        """Run blocklist download & parsing in background thread."""
        if self.is_updating:
            return False
        threading.Thread(target=self._update_blocklists_worker, args=(callback,), daemon=True).start()
        return True

    def _update_blocklists_worker(self, callback=None):
        self.is_updating = True
        self.last_update_status = "Mengunduh pembaruan blocklist..."
        sources = self.config_mgr.get("blocklist_sources", [])

        try:
            for src in sources:
                if not src.get("enabled", True):
                    continue
                src_id = src.get("id")
                url = src.get("url")
                name = src.get("name")
                self.last_update_status = f"Mengunduh {name}..."
                print(f"[BlocklistManager] Updating {name} from {url}...")

                try:
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdShield-DNS/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=25) as res:
                        content = res.read().decode("utf-8", errors="ignore")
                        domains = set()
                        for line in content.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                d = parts[1].lower().rstrip(".")
                                if ip in ("0.0.0.0", "127.0.0.1") and d not in ("localhost", "local", "broadcasthost", "0.0.0.0"):
                                    domains.add(d)
                            elif len(parts) == 1 and "." in parts[0]:
                                domains.add(parts[0].lower().rstrip("."))

                        # Save cache
                        cache_file = os.path.join(self.data_dir, f"cache_{src_id}.txt")
                        with open(cache_file, "w", encoding="utf-8") as cf:
                            for d in sorted(domains):
                                cf.write(d + "\n")

                        # Update metadata
                        src["count"] = len(domains)
                        src["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    print(f"[BlocklistManager] Failed to update {name}: {e}")

            self.config_mgr.set("blocklist_sources", sources)
            self.reload_all()
            self.last_update_status = f"Pembaruan selesai! {len(self.blocked_domains)} aturan aktif."
        except Exception as e:
            self.last_update_status = f"Gagal memperbarui: {e}"
        finally:
            self.is_updating = False
            if callback:
                callback()

    def get_stats(self) -> dict:
        with self.lock:
            return {
                "total_blocked_rules": len(self.blocked_domains),
                "custom_whitelist_count": len(self.custom_whitelist),
                "custom_blacklist_count": len(self.custom_blacklist),
                "is_updating": self.is_updating,
                "update_status": self.last_update_status
            }
