"""
Web Server and REST API for AdShield DNS
Powered by Bottle with ThreadedWSGIServer.
"""

import os
import sys
import json
import threading
import time
from wsgiref.simple_server import make_server, WSGIServer
from socketserver import ThreadingMixIn

import bottle
from bottle import Bottle, request, response, static_file, abort

from windows_utils import (
    get_lan_ips, is_autostart_enabled, set_autostart,
    get_active_adapter_name, is_local_dns_applied, apply_local_dns, reset_local_dns,
    get_power_status, open_lid_power_settings, get_device_discovery,
    is_windows_service_installed, install_windows_service, uninstall_windows_service,
    get_adapter_ip_info, lock_adapter_ip, unlock_adapter_ip
)
from blocklist_manager import SERVICE_CATALOG
from license_manager import LicenseManager
import dns.message
import dns.query
import dns.rdatatype

class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True

class WebServer:
    def __init__(self, config_mgr, blocklist_mgr, dns_engine, static_dir: str):
        self.config_mgr = config_mgr
        self.blocklist_mgr = blocklist_mgr
        self.dns_engine = dns_engine
        self.static_dir = static_dir
        self.license_mgr = LicenseManager(self.config_mgr.data_dir)

        self.app = Bottle()
        self.server = None
        self.thread = None
        self._setup_routes()

    def _setup_routes(self):
        app = self.app

        @app.hook('after_request')
        def enable_cors():
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token'

        @app.route('/')
        def index():
            return static_file('index.html', root=self.static_dir)

        @app.route('/favicon.ico')
        def serve_favicon():
            response.headers['Cache-Control'] = 'public, max-age=86400'
            for d in [self.static_dir, os.path.join(os.path.dirname(self.static_dir), "data")]:
                if os.path.exists(os.path.join(d, "icon.ico")):
                    return static_file("icon.ico", root=d, mimetype="image/x-icon")
            return static_file("index.html", root=self.static_dir)

        @app.route('/icon.png')
        def serve_root_icon():
            response.headers['Cache-Control'] = 'public, max-age=86400'
            for d in [self.static_dir, os.path.join(os.path.dirname(self.static_dir), "data")]:
                if os.path.exists(os.path.join(d, "icon.png")):
                    return static_file("icon.png", root=d, mimetype="image/png")
            return static_file("index.html", root=self.static_dir)

        @app.route('/static/<filename:path>')
        def serve_static(filename):
            return static_file(filename, root=self.static_dir)

        @app.route('/api/overview', method='GET')
        def api_overview():
            response.content_type = 'application/json'
            dns_stats = self.dns_engine.get_stats_overview()
            block_stats = self.blocklist_mgr.get_stats()
            lan_ips = get_lan_ips()
            adapter = get_active_adapter_name()
            local_dns = is_local_dns_applied(adapter)
            power_status = get_power_status()
            adapter_ip_info = get_adapter_ip_info(adapter)
            license_info = self.license_mgr.get_status()

            return json.dumps({
                "status": "success",
                "dns": dns_stats,
                "blocklist": block_stats,
                "lan_ips": lan_ips,
                "adapter_name": adapter,
                "is_local_dns_applied": local_dns,
                "adapter_ip_info": adapter_ip_info,
                "license": license_info,
                "upstream_provider": self.config_mgr.get("upstream_provider", "Cloudflare"),
                "upstream_dns": self.config_mgr.get("upstream_dns", ["1.1.1.1", "1.0.0.1"]),
                "doh_enabled": self.config_mgr.get("doh_enabled", True),
                "doh_only": self.config_mgr.get("doh_only", False),
                "is_blocking_active": self.config_mgr.is_blocking_active(),
                "pause_until": self.config_mgr.get("pause_until", 0),
                "autostart": is_autostart_enabled(),
                "is_service_installed": is_windows_service_installed(),
                "power_status": power_status,
                "services_blocked": self.config_mgr.get("services_blocked", {})
            })

        @app.route('/api/adapter-dns/apply', method='POST')
        def api_apply_local_dns():
            response.content_type = 'application/json'
            adapter = get_active_adapter_name()
            success = apply_local_dns(adapter)
            if success:
                return json.dumps({"status": "success", "message": f"DNS AdShield berhasil diterapkan ke adapter '{adapter}'"})
            response.status = 500
            return json.dumps({"status": "error", "message": f"Gagal menerapkan DNS ke adapter '{adapter}'"})

        @app.route('/api/adapter-dns/reset', method='POST')
        def api_reset_local_dns():
            response.content_type = 'application/json'
            adapter = get_active_adapter_name()
            success = reset_local_dns(adapter)
            if success:
                return json.dumps({"status": "success", "message": f"DNS adapter '{adapter}' dikembalikan ke otomatis (DHCP)"})
            response.status = 500
            return json.dumps({"status": "error", "message": f"Gagal mereset DNS adapter '{adapter}'"})

        @app.route('/api/adapter-ip/status', method='GET')
        def api_adapter_ip_status():
            response.content_type = 'application/json'
            adapter = get_active_adapter_name()
            info = get_adapter_ip_info(adapter)
            return json.dumps({"status": "success", "info": info})

        @app.route('/api/adapter-ip/lock', method='POST')
        def api_adapter_ip_lock():
            response.content_type = 'application/json'
            if not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Fitur Penguncian IP Permanen (Anti-Berubah) adalah fitur PRO eksklusif AdShield! Masukkan kode lisensi atau kupon untuk mengaktifkannya."
                })
            adapter = get_active_adapter_name()
            success = lock_adapter_ip(adapter)
            if success:
                info = get_adapter_ip_info(adapter)
                return json.dumps({"status": "success", "message": f"IP {info['ip']} berhasil dikunci permanen (Static IP)!", "info": info})
            response.status = 500
            return json.dumps({"status": "error", "message": "Gagal mengunci IP. Pastikan izin Administrator aktif."})

        @app.route('/api/adapter-ip/unlock', method='POST')
        def api_adapter_ip_unlock():
            response.content_type = 'application/json'
            adapter = get_active_adapter_name()
            success = unlock_adapter_ip(adapter)
            if success:
                info = get_adapter_ip_info(adapter)
                return json.dumps({"status": "success", "message": "IP adapter dikembalikan ke otomatis (DHCP)!", "info": info})
            response.status = 500
            return json.dumps({"status": "error", "message": "Gagal mengubah ke DHCP."})

        @app.route('/api/license/status', method='GET')
        def api_license_status():
            response.content_type = 'application/json'
            return json.dumps({"status": "success", "license": self.license_mgr.get_status()})

        @app.route('/api/license/activate', method='POST')
        def api_license_activate():
            response.content_type = 'application/json'
            data = request.json or {}
            code = data.get("code", "").strip()
            res = self.license_mgr.activate_code(code)
            if not res["success"]:
                response.status = 400
            return json.dumps(res)

        @app.route('/api/dns-test', method='POST')
        def api_dns_test():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "adservice.google.com").strip().rstrip(".")
            if not domain:
                domain = "adservice.google.com"
            try:
                lan_ips = get_lan_ips()
                target_ip = lan_ips[0] if lan_ips else "127.0.0.1"
                q = dns.message.make_query(domain + ".", dns.rdatatype.A)
                res = dns.query.udp(q, target_ip, port=53, timeout=3.0)
                answers = []
                is_sinkhole = False
                if res.answer:
                    for rrset in res.answer:
                        for item in rrset:
                            ans_str = item.to_text()
                            answers.append(ans_str)
                            if ans_str in ("0.0.0.0", "::"):
                                is_sinkhole = True
                return json.dumps({
                    "status": "success",
                    "domain": domain,
                    "is_blocked": is_sinkhole,
                    "answers": answers,
                    "target_dns": target_ip
                })
            except Exception as e:
                return json.dumps({"status": "error", "message": str(e)})

        # Per-Client Management Endpoints (Beda Aturan Tiap HP / Device)
        @app.route('/api/clients', method='GET')
        def api_get_clients():
            response.content_type = 'application/json'
            configured = self.config_mgr.get("clients", [])
            discovered = get_device_discovery()

            # Merge discovered device metadata
            configured_ips = {c.get("ip"): c for c in configured}
            all_devices = []

            for d in discovered:
                ip = d.get("ip")
                if ip in configured_ips:
                    entry = configured_ips[ip].copy()
                    entry["mac"] = d.get("mac")
                    entry["vendor"] = d.get("vendor")
                    entry["configured"] = True
                    all_devices.append(entry)
                else:
                    all_devices.append({
                        "ip": ip,
                        "name": d.get("vendor"),
                        "mac": d.get("mac"),
                        "vendor": d.get("vendor"),
                        "profile": "standard",
                        "safesearch": False,
                        "blocked_services": [],
                        "configured": False
                    })

            for c in configured:
                if not any(d.get("ip") == c.get("ip") for d in discovered):
                    entry = c.copy()
                    entry["configured"] = True
                    all_devices.append(entry)

            return json.dumps({
                "status": "success",
                "devices": all_devices,
                "configured_clients": configured
            })

        @app.route('/api/clients/save', method='POST')
        def api_save_client():
            response.content_type = 'application/json'
            data = request.json or {}
            ip = data.get("ip", "").strip()
            name = data.get("name", "").strip() or ip
            profile = data.get("profile", "standard")
            safesearch = bool(data.get("safesearch", False))
            blocked_services = data.get("blocked_services", [])

            if not ip:
                response.status = 400
                return json.dumps({"status": "error", "message": "IP klien wajib diisi"})

            clients = self.config_mgr.get("clients", [])
            clients = [c for c in clients if c.get("ip") != ip]
            clients.append({
                "ip": ip,
                "name": name,
                "profile": profile,
                "safesearch": safesearch,
                "blocked_services": blocked_services
            })
            self.config_mgr.set("clients", clients)
            return json.dumps({"status": "success", "message": f"Pengaturan untuk klien '{name}' ({ip}) berhasil disimpan"})

        @app.route('/api/clients/delete', method='POST')
        def api_delete_client():
            response.content_type = 'application/json'
            data = request.json or {}
            ip = data.get("ip", "").strip()
            clients = self.config_mgr.get("clients", [])
            clients = [c for c in clients if c.get("ip") != ip]
            self.config_mgr.set("clients", clients)
            return json.dumps({"status": "success", "message": f"Klien {ip} telah dihapus dari aturan khusus"})

        # Quick Blocked Services API
        @app.route('/api/services', method='GET')
        def api_get_services():
            response.content_type = 'application/json'
            services_cfg = self.config_mgr.get("services_blocked", {})
            catalog = []
            for s_id, s_info in SERVICE_CATALOG.items():
                catalog.append({
                    "id": s_id,
                    "name": s_info["name"],
                    "domains_count": len(s_info["domains"]),
                    "enabled": bool(services_cfg.get(s_id, False))
                })
            return json.dumps({
                "status": "success",
                "services": catalog,
                "safesearch": bool(services_cfg.get("safesearch", False))
            })

        @app.route('/api/services/toggle', method='POST')
        def api_toggle_service():
            response.content_type = 'application/json'
            data = request.json or {}
            s_id = data.get("service")
            enabled = bool(data.get("enabled", False))
            services_cfg = self.config_mgr.get("services_blocked", {})
            services_cfg[s_id] = enabled
            self.config_mgr.set("services_blocked", services_cfg)
            return json.dumps({"status": "success", "message": f"Pengaturan layanan '{s_id}' diperbarui"})

        # Upstream Speed Benchmark API
        @app.route('/api/benchmark', method='GET')
        def api_benchmark():
            response.content_type = 'application/json'
            if not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Uji Benchmark Latensi Nyata 7 Server Upstream adalah fitur PRO eksklusif AdShield! Masukkan kode lisensi atau kupon untuk mengaktifkannya.",
                    "results": []
                })
            results = self.dns_engine.benchmark_upstreams()
            return json.dumps({
                "status": "success",
                "results": results
            })

        # Anti-ISP Hijack (DoH Only) Toggle
        @app.route('/api/settings/doh-only', method='POST')
        def api_toggle_doh_only():
            response.content_type = 'application/json'
            data = request.json or {}
            enabled = bool(data.get("doh_only", False))
            if enabled and not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Mode Anti-ISP Hijacking (Encrypted DoH) adalah fitur PRO eksklusif AdShield!"
                })
            self.config_mgr.set("doh_only", enabled)
            return json.dumps({"status": "success", "doh_only": enabled})

        # Local DNS Rewrites
        @app.route('/api/rewrites', method='GET')
        def api_get_rewrites():
            response.content_type = 'application/json'
            return json.dumps({
                "status": "success",
                "rewrites": self.config_mgr.get("dns_rewrites", [])
            })

        @app.route('/api/rewrites/add', method='POST')
        def api_add_rewrite():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip().lower().rstrip(".")
            ip = data.get("ip", "").strip()
            if not domain or not ip:
                response.status = 400
                return json.dumps({"status": "error", "message": "Domain dan IP wajib diisi"})
            rewrites = self.config_mgr.get("dns_rewrites", [])
            rewrites = [r for r in rewrites if r.get("domain") != domain]
            rewrites.append({"domain": domain, "ip": ip})
            self.config_mgr.set("dns_rewrites", rewrites)
            return json.dumps({"status": "success", "message": f"{domain} -> {ip} disimpan"})

        @app.route('/api/rewrites/remove', method='POST')
        def api_remove_rewrite():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip().lower().rstrip(".")
            rewrites = self.config_mgr.get("dns_rewrites", [])
            rewrites = [r for r in rewrites if r.get("domain") != domain]
            self.config_mgr.set("dns_rewrites", rewrites)
            return json.dumps({"status": "success"})

        # Logs API (supports persistent DB search)
        @app.route('/api/logs', method='GET')
        def api_logs():
            response.content_type = 'application/json'
            limit = int(request.query.get('limit', 100))
            filter_type = request.query.get('filter', 'ALL')
            search = request.query.get('search', '').strip()

            if search:
                logs = self.dns_engine.db.get_recent_logs(limit=limit, filter_type=filter_type, search=search)
            else:
                logs = self.dns_engine.get_query_log(limit=limit, filter_type=filter_type)
            return json.dumps({"status": "success", "logs": logs})

        @app.route('/api/pause', method='POST')
        def api_pause():
            response.content_type = 'application/json'
            try:
                data = request.json or {}
                duration_min = int(data.get('duration_minutes', 5))
                if duration_min > 0:
                    self.config_mgr.pause_blocking(duration_min * 60)
                else:
                    self.config_mgr.pause_blocking(0)
                return json.dumps({"status": "success", "message": f"Pemblokiran dijeda ({duration_min} menit)"})
            except Exception as e:
                response.status = 400
                return json.dumps({"status": "error", "message": str(e)})

        @app.route('/api/resume', method='POST')
        def api_resume():
            response.content_type = 'application/json'
            self.config_mgr.resume_blocking()
            return json.dumps({"status": "success", "message": "Pemblokiran aktif kembali"})

        @app.route('/api/lists', method='GET')
        def api_lists():
            response.content_type = 'application/json'
            return json.dumps({
                "status": "success",
                "sources": self.config_mgr.get("blocklist_sources", []),
                "whitelist": sorted(list(self.blocklist_mgr.custom_whitelist)),
                "blacklist": sorted(list(self.blocklist_mgr.custom_blacklist)),
                "stats": self.blocklist_mgr.get_stats()
            })

        @app.route('/api/lists/update', method='POST')
        def api_update_lists():
            response.content_type = 'application/json'
            success = self.blocklist_mgr.update_blocklists_async()
            if success:
                return json.dumps({"status": "success", "message": "Pembaruan blocklist dimulai di latar belakang"})
            else:
                return json.dumps({"status": "busy", "message": "Pembaruan sedang berjalan"})

        @app.route('/api/lists/toggle', method='POST')
        def api_toggle_list():
            response.content_type = 'application/json'
            data = request.json or {}
            src_id = data.get("id")
            enabled = bool(data.get("enabled", True))
            sources = self.config_mgr.get("blocklist_sources", [])
            for s in sources:
                if s.get("id") == src_id:
                    s["enabled"] = enabled
                    break
            self.config_mgr.set("blocklist_sources", sources)
            self.blocklist_mgr.reload_all()
            return json.dumps({"status": "success"})

        @app.route('/api/lists/add', method='POST')
        def api_add_list():
            response.content_type = 'application/json'
            data = request.json or {}
            name = data.get("name", "").strip()
            url = data.get("url", "").strip()
            if not name or not url.startswith("http"):
                response.status = 400
                return json.dumps({"status": "error", "message": "Nama atau URL tidak valid"})

            src_id = f"custom_{int(time.time())}"
            sources = self.config_mgr.get("blocklist_sources", [])
            sources.append({
                "id": src_id,
                "name": name,
                "url": url,
                "enabled": True,
                "count": 0,
                "last_updated": "Belum diupdate"
            })
            self.config_mgr.set("blocklist_sources", sources)
            self.blocklist_mgr.update_blocklists_async()
            return json.dumps({"status": "success", "message": "Sumber berhasil ditambahkan"})

        @app.route('/api/custom/whitelist', method='POST')
        def api_add_whitelist():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip()
            if self.blocklist_mgr.add_to_whitelist(domain):
                return json.dumps({"status": "success", "message": f"{domain} ditambahkan ke Whitelist"})
            response.status = 400
            return json.dumps({"status": "error", "message": "Domain tidak valid"})

        @app.route('/api/custom/whitelist/remove', method='POST')
        def api_remove_whitelist():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip()
            self.blocklist_mgr.remove_from_whitelist(domain)
            return json.dumps({"status": "success"})

        @app.route('/api/custom/blacklist', method='POST')
        def api_add_blacklist():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip()
            if self.blocklist_mgr.add_to_blacklist(domain):
                return json.dumps({"status": "success", "message": f"{domain} ditambahkan ke Blacklist"})
            response.status = 400
            return json.dumps({"status": "error", "message": "Domain tidak valid"})

        @app.route('/api/custom/blacklist/remove', method='POST')
        def api_remove_blacklist():
            response.content_type = 'application/json'
            data = request.json or {}
            domain = data.get("domain", "").strip()
            self.blocklist_mgr.remove_from_blacklist(domain)
            return json.dumps({"status": "success"})

        # Teleporter: Backup & Restore
        @app.route('/api/teleporter/export', method='GET')
        def api_teleporter_export():
            response.content_type = 'application/json'
            if not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Teleporter Backup & Restore adalah fitur PRO eksklusif AdShield!"
                })
            response.headers['Content-Disposition'] = 'attachment; filename="adshield_backup.json"'
            backup_data = {
                "version": "1.0",
                "export_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "config": self.config_mgr.config,
                "whitelist": sorted(list(self.blocklist_mgr.custom_whitelist)),
                "blacklist": sorted(list(self.blocklist_mgr.custom_blacklist))
            }
            return json.dumps(backup_data, indent=2)

        @app.route('/api/teleporter/import', method='POST')
        def api_teleporter_import():
            response.content_type = 'application/json'
            if not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Teleporter Backup & Restore adalah fitur PRO eksklusif AdShield!"
                })
            try:
                data = request.json or {}
                if "config" in data:
                    self.config_mgr.config.update(data["config"])
                    self.config_mgr.save()
                if "whitelist" in data:
                    self.blocklist_mgr.custom_whitelist = set(data["whitelist"])
                    self.blocklist_mgr._save_set_to_file(self.blocklist_mgr.whitelist_file, self.blocklist_mgr.custom_whitelist, "Custom Whitelist")
                if "blacklist" in data:
                    self.blocklist_mgr.custom_blacklist = set(data["blacklist"])
                    self.blocklist_mgr._save_set_to_file(self.blocklist_mgr.blacklist_file, self.blocklist_mgr.custom_blacklist, "Custom Blacklist")
                self.blocklist_mgr.reload_all()
                return json.dumps({"status": "success", "message": "Konfigurasi berhasil dipulihkan dari backup!"})
            except Exception as e:
                response.status = 400
                return json.dumps({"status": "error", "message": f"Gagal restore backup: {e}"})

        # Windows Service Management Endpoints
        @app.route('/api/windows-service/install', method='POST')
        def api_service_install():
            response.content_type = 'application/json'
            if not self.license_mgr.is_pro():
                return json.dumps({
                    "status": "pro_required",
                    "message": "Pemasangan resmi Windows Service adalah fitur PRO eksklusif AdShield!"
                })
            success = install_windows_service()
            if success:
                return json.dumps({"status": "success", "message": "AdShield berhasil didaftarkan sebagai Windows Service resmi!"})
            response.status = 500
            return json.dumps({"status": "error", "message": "Gagal mendaftarkan Windows Service. Pastikan izin Administrator."})

        @app.route('/api/windows-service/uninstall', method='POST')
        def api_service_uninstall():
            response.content_type = 'application/json'
            success = uninstall_windows_service()
            if success:
                return json.dumps({"status": "success", "message": "AdShield Windows Service berhasil dihapus."})
            response.status = 500
            return json.dumps({"status": "error", "message": "Gagal menghapus Windows Service."})

        # Laptop Lid Power Options
        @app.route('/api/laptop/open-lid-settings', method='POST')
        def api_open_lid_settings():
            response.content_type = 'application/json'
            success = open_lid_power_settings()
            return json.dumps({"status": "success" if success else "error"})

        @app.route('/api/settings', method='GET')
        def api_get_settings():
            response.content_type = 'application/json'
            return json.dumps({
                "status": "success",
                "upstream_provider": self.config_mgr.get("upstream_provider", "Cloudflare"),
                "upstream_dns": self.config_mgr.get("upstream_dns", ["1.1.1.1", "1.0.0.1"]),
                "blocking_mode": self.config_mgr.get("blocking_mode", "0.0.0.0"),
                "autostart": is_autostart_enabled(),
                "doh_enabled": self.config_mgr.get("doh_enabled", True),
                "doh_only": self.config_mgr.get("doh_only", False),
                "rate_limit_enabled": self.config_mgr.get("rate_limit_enabled", True),
                "rate_limit_rps": self.config_mgr.get("rate_limit_rps", 100),
                "optimistic_cache": self.config_mgr.get("optimistic_cache", True)
            })

        @app.route('/api/settings', method='POST')
        def api_save_settings():
            response.content_type = 'application/json'
            data = request.json or {}
            provider = data.get("upstream_provider")
            custom_dns = data.get("custom_dns")
            blocking_mode = data.get("blocking_mode")
            autostart = data.get("autostart")
            doh_only = data.get("doh_only")
            rate_limit_enabled = data.get("rate_limit_enabled")
            rate_limit_rps = data.get("rate_limit_rps")

            if provider:
                self.config_mgr.set_upstream(provider, custom_dns)
            if blocking_mode:
                self.config_mgr.set("blocking_mode", blocking_mode)
            if autostart is not None:
                set_autostart(bool(autostart))
            if doh_only is not None:
                self.config_mgr.set("doh_only", bool(doh_only))
            if rate_limit_enabled is not None:
                self.config_mgr.set("rate_limit_enabled", bool(rate_limit_enabled))
            if rate_limit_rps:
                self.config_mgr.set("rate_limit_rps", int(rate_limit_rps))

            return json.dumps({"status": "success", "message": "Pengaturan berhasil disimpan"})

        @app.route('/api/cache/clear', method='POST')
        def api_clear_cache():
            response.content_type = 'application/json'
            self.dns_engine.clear_cache()
            return json.dumps({"status": "success", "message": "Cache DNS berhasil dikosongkan"})

    def start(self):
        port = self.config_mgr.get("web_port", 5380)
        try:
            self.server = make_server("0.0.0.0", port, self.app, server_class=ThreadedWSGIServer)
            self.thread = threading.Thread(target=self.server.serve_forever, name="Web-Server-Worker", daemon=True)
            self.thread.start()
            print(f"[WebServer] Dashboard running on http://localhost:{port}")
        except Exception as e:
            print(f"[WebServer] Failed to start on port {port}: {e}")

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
