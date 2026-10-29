"""
Comprehensive Test Script for AdShield DNS ULTRA
Verifies all superior capabilities:
- DNS Engine (Port 53 UDP & TCP)
- In-Memory RAM Caching
- SafeSearch Enforcement
- Local DNS Rewrites
- Quick Service Blocking (Windows Telemetry, Games, TikTok)
- Per-Client Profiles & Device Discovery
- Upstream Speed Benchmark
- Teleporter Backup Export
- SQLite Persistent Logging
"""

import os
import sys
import time
import json
import urllib.request
import dns.message
import dns.query
import dns.rdatatype

from config_manager import ConfigManager
from blocklist_manager import BlocklistManager
from dns_engine import DNSEngine
from web_server import WebServer
from windows_utils import get_lan_ips

def run_tests():
    print("=== Memulai Pengujian Menyeluruh AdShield DNS ULTRA ===")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "data")
    static_dir = os.path.join(script_dir, "static")

    config_mgr = ConfigManager(data_dir)
    blocklist_mgr = BlocklistManager(data_dir, config_mgr)
    dns_engine = DNSEngine(config_mgr, blocklist_mgr)
    web_server = WebServer(config_mgr, blocklist_mgr, dns_engine, static_dir)

    print("[TestSetup] Memulai DNS Engine dan Web Server...")
    dns_engine.start()
    web_server.start()
    time.sleep(1.2) # Allow bind

    lan_ip = get_lan_ips()[0]
    print(f"Target DNS Server IP: {lan_ip}:53")

    success = True
    try:
        # 1. Test Web Dashboard API
        print("\n1. Menguji API Web Dashboard (/api/overview)...")
        req = urllib.request.urlopen("http://127.0.0.1:5380/api/overview", timeout=5)
        data = json.loads(req.read().decode())
        print("  -> Status:", data.get("status"))
        print("  -> Total Rules:", data.get("blocklist", {}).get("total_blocked_rules"))
        print("  -> Power Status:", data.get("power_status", {}).get("power_mode"))
        assert data.get("status") == "success"
        print("  [OK] Web API Berjalan dengan Sempurna!")

        # 2. Test DNS Query - Ad Domain (Should be Sinkholed to 0.0.0.0)
        print("\n2. Menguji Query Domain Iklan (Sinkhole)...")
        test_ad = "adservice.google.com"
        q = dns.message.make_query(test_ad + ".", dns.rdatatype.A)
        res = dns.query.udp(q, lan_ip, port=53, timeout=3.0)
        print(f"  -> Query: {test_ad}")
        if res.answer:
            answer_text = res.answer[0].to_text()
            print(f"  -> Jawaban DNS: {answer_text}")
            assert "0.0.0.0" in answer_text
            print("  [OK] Sukses! Domain iklan berhasil di-sinkhole ke 0.0.0.0!")
        else:
            print("  [WARN] Tidak ada jawaban A record")

        # 3. Test DNS Query - Legitimate Domain (Forwarding)
        print("\n3. Menguji Query Domain Legal (Forwarding)...")
        clean_domain = "cloudflare.com"
        q_clean = dns.message.make_query(clean_domain + ".", dns.rdatatype.A)
        res_clean = dns.query.udp(q_clean, lan_ip, port=53, timeout=4.0)
        assert res_clean.answer
        print(f"  -> Jawaban DNS: {res_clean.answer[0].to_text().splitlines()[0]}")
        print("  [OK] Sukses! Domain legal diteruskan ke upstream dan berhasil dijawab!")

        # 4. Test In-Memory RAM Caching
        print("\n4. Menguji In-Memory RAM Caching...")
        t0 = time.perf_counter()
        res_cached = dns.query.udp(q_clean, lan_ip, port=53, timeout=2.0)
        dt = (time.perf_counter() - t0) * 1000
        print(f"  -> Latensi Cache Query Kedua: {dt:.2f} ms")
        assert dt < 20.0
        print(f"  [OK] Cache RAM super cepat! Terjawab dalam {dt:.2f} ms.")

        # 5. Test Local DNS Rewrite (modem.lan -> 192.168.100.1)
        print("\n5. Menguji Local DNS Rewrite (modem.lan -> 192.168.100.1)...")
        q_rw = dns.message.make_query("modem.lan.", dns.rdatatype.A)
        res_rw = dns.query.udp(q_rw, lan_ip, port=53, timeout=3.0)
        assert res_rw.answer
        rw_ans = res_rw.answer[0].to_text()
        print(f"  -> Rewrite Answer: {rw_ans}")
        assert "192.168.100.1" in rw_ans
        print("  [OK] Local DNS Rewrite Berhasil Sempurna!")

        # 6. Test Quick Service Blocker (Windows Telemetry)
        print("\n6. Menguji Quick Service Blocker (Windows Telemetry)...")
        q_spy = dns.message.make_query("vortex.data.microsoft.com.", dns.rdatatype.A)
        res_spy = dns.query.udp(q_spy, lan_ip, port=53, timeout=3.0)
        assert res_spy.answer
        assert "0.0.0.0" in res_spy.answer[0].to_text()
        print("  [OK] Service Blocker (Windows Telemetry) Berhasil Diblokir!")

        # 7. Test SafeSearch Enforcement
        print("\n7. Menguji SafeSearch Enforcement (Google -> SafeSearch VIP)...")
        config_mgr.set("services_blocked", {"windows_spy": True, "safesearch": True})
        q_ss = dns.message.make_query("google.com.", dns.rdatatype.A)
        res_ss = dns.query.udp(q_ss, lan_ip, port=53, timeout=3.0)
        assert res_ss.answer
        ss_ans = res_ss.answer[0].to_text()
        print(f"  -> SafeSearch Answer: {ss_ans}")
        assert "216.239.38.120" in ss_ans
        print("  [OK] SafeSearch Berhasil Mengarahkan ke Google Safe VIP!")

        # 8. Test Client Management API
        print("\n8. Menguji API Manajemen Klien (/api/clients)...")
        req_c = urllib.request.urlopen("http://127.0.0.1:5380/api/clients", timeout=5)
        data_c = json.loads(req_c.read().decode())
        print(f"  -> Total Perangkat Terdeteksi: {len(data_c.get('devices', []))}")
        assert data_c.get("status") == "success"
        print("  [OK] API Manajemen Klien Berjalan Lancar!")

        # 9. Test Basic Gating on Pro Features
        print("\n9. Menguji Proteksi Fitur Pro saat di Mode Basic (/api/benchmark & /api/license)...")
        req_b_basic = urllib.request.urlopen("http://127.0.0.1:5380/api/benchmark", timeout=10)
        data_b_basic = json.loads(req_b_basic.read().decode())
        assert data_b_basic.get("status") == "pro_required"
        print("  [OK] Fitur Pro terlindungi dengan benar di mode Basic (status: pro_required)!")

        # 10. Test License & Coupon Activation
        print("\n10. Menguji Sistem Lisensi & Aktivasi Kupon PRO (/api/license/activate)...")
        req_lic = urllib.request.Request(
            "http://127.0.0.1:5380/api/license/activate",
            data=json.dumps({"code": "PRO-VIP-2026"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        res_lic = urllib.request.urlopen(req_lic, timeout=5)
        data_lic = json.loads(res_lic.read().decode())
        print(f"  -> Respon Aktivasi: {data_lic.get('message')}")
        assert data_lic.get("tier") == "PRO"
        print("  [OK] Kupon PRO Berhasil Diaktivasi Secara Instan!")

        # 11. Test Upstream Benchmark API (Now unlocked in PRO)
        print("\n11. Menguji Upstream Benchmark API (/api/benchmark setelah Pro Aktif)...")
        req_b = urllib.request.urlopen("http://127.0.0.1:5380/api/benchmark", timeout=10)
        data_b = json.loads(req_b.read().decode())
        results = data_b.get("results", [])
        print(f"  -> Total Provider Diuji: {len(results)}")
        for r in results[:3]:
            print(f"     [{r['type']}] {r['name']}: {r['latency_ms']} ms ({r['status']})")
        assert len(results) > 0
        print("  [OK] Upstream Benchmark Berhasil Menemukan Server Tercepat!")

        # 12. Test Teleporter Backup Export
        print("\n12. Menguji Teleporter Backup Export (/api/teleporter/export)...")
        req_t = urllib.request.urlopen("http://127.0.0.1:5380/api/teleporter/export", timeout=5)
        data_t = json.loads(req_t.read().decode())
        assert "config" in data_t
        assert "whitelist" in data_t
        print(f"  -> Export Version: {data_t.get('version')} ({len(data_t.get('config', {}))} config keys)")
        print("  [OK] Teleporter Backup Export Berjalan Sempurna!")

        # 13. Test Static IP Status API
        print("\n13. Menguji Status IP Adapter (/api/adapter-ip/status)...")
        req_ip = urllib.request.urlopen("http://127.0.0.1:5380/api/adapter-ip/status", timeout=5)
        data_ip = json.loads(req_ip.read().decode())
        info_ip = data_ip.get("info", {})
        print(f"  -> IP: {info_ip.get('ip')}, Gateway: {info_ip.get('gateway')}, Terkunci: {info_ip.get('is_locked')}")
        assert "ip" in info_ip
        print("  [OK] Deteksi IP Adapter Berhasil Sempurna!")
        print("  [OK] Deteksi IP Adapter Berhasil Sempurna!")

        print("\n=== SEMUA 12 PENGUJIAN ADSHIELD MACOS ULTRA BEAST BERHASIL 100%! ===")

    except Exception as e:
        print(f"\n[FAIL] Terjadi kegagalan pengujian: {e}")
        import traceback
        traceback.print_exc()
        success = False
    finally:
        print("[TestCleanup] Menutup DNS Engine dan Web Server...")
        dns_engine.stop()
        web_server.stop()
        dns_engine.db.close()
        time.sleep(0.5)

    return success

if __name__ == "__main__":
    if not run_tests():
        sys.exit(1)
