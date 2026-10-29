"""
High-Performance DNS Engine with Sinkholing, Caching, and Stats Logging
Supports UDP and TCP on port 53.
"""

import socket
import select
import struct
import threading
import time
import queue
import urllib.request
import concurrent.futures
from collections import deque, Counter
from typing import Dict, Tuple, Optional

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset
import dns.rcode

from database import QueryDatabase
from blocklist_manager import SERVICE_CATALOG

SAFESEARCH_MAPPINGS = {
    "google": {
        "domains": {"google.com", "www.google.com", "google.co.id", "www.google.co.id"},
        "ip": "216.239.38.120"
    },
    "bing": {
        "domains": {"bing.com", "www.bing.com"},
        "ip": "204.79.197.220"
    },
    "duckduckgo": {
        "domains": {"duckduckgo.com", "www.duckduckgo.com"},
        "ip": "52.142.124.215"
    },
    "youtube": {
        "domains": {"youtube.com", "www.youtube.com", "m.youtube.com"},
        "ip": "216.239.38.119"
    }
}

class DNSEngine:
    def __init__(self, config_mgr, blocklist_mgr):
        self.config_mgr = config_mgr
        self.blocklist_mgr = blocklist_mgr

        self.running = False
        self.udp_sock = None
        self.tcp_sock = None
        self.threads = []

        # In-Memory Cache: key=(qname, qtype) -> (wire_data: bytes, expire_at: float)
        self.cache: Dict[Tuple[str, int], Tuple[bytes, float]] = {}
        # Stale Cache for Optimistic Caching (Serve Stale if upstream is down)
        self.stale_cache: Dict[Tuple[str, int], bytes] = {}
        self.cache_lock = threading.RLock()

        # Persistent SQLite Database
        self.db = QueryDatabase(self.config_mgr.data_dir)
        # Rate Limiting Tracker: client_ip -> (count, second_timestamp)
        self.rate_limits: Dict[str, Tuple[int, int]] = {}

        # Query Log & Metrics
        self.query_log = deque(maxlen=1000)
        self.log_lock = threading.RLock()

        # Cumulative counters
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "cached_queries": 0,
            "forwarded_queries": 0,
            "start_time": time.time(),
            "avg_latency_ms": 0.0
        }
        self.total_latency_sum = 0.0
        self.total_latency_count = 0

        # Aggregations
        self.top_blocked = Counter()
        self.top_allowed = Counter()
        self.top_clients = Counter()
        self.hourly_queries = Counter()

    def start(self):
        """Bind sockets and start worker threads."""
        port = self.config_mgr.get("dns_port", 53)
        self.running = True

        # 1. Bind UDP Socket
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind(("0.0.0.0", port))
            print(f"[DNSEngine] UDP listener bound on 0.0.0.0:{port}")
        except Exception as e:
            self.running = False
            raise RuntimeError(f"Gagal mengikat port {port} (UDP). Pastikan aplikasi dijalankan sebagai Administrator dan port 53 tidak dipakai aplikasi lain: {e}")

        # 2. Bind TCP Socket
        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind(("0.0.0.0", port))
            self.tcp_sock.listen(20)
            print(f"[DNSEngine] TCP listener bound on 0.0.0.0:{port}")
        except Exception as e:
            print(f"[DNSEngine] Warning: TCP listener failed on port {port}: {e}")

        # Start UDP worker threads (4 workers for concurrency)
        for i in range(4):
            t = threading.Thread(target=self._udp_worker, name=f"DNS-UDP-Worker-{i}", daemon=True)
            t.start()
            self.threads.append(t)

        # Start TCP accept worker
        if self.tcp_sock:
            t = threading.Thread(target=self._tcp_worker, name="DNS-TCP-Worker", daemon=True)
            t.start()
            self.threads.append(t)

        # Cache cleanup thread
        t = threading.Thread(target=self._cache_cleanup_worker, name="DNS-Cache-Cleanup", daemon=True)
        t.start()
        self.threads.append(t)

    def stop(self):
        """Stop server and close sockets."""
        self.running = False
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass

    def _check_rate_limit(self, client_ip: str) -> bool:
        """Returns True if allowed, False if exceeded rate limit."""
        if not self.config_mgr.get("rate_limit_enabled", True):
            return True
        max_rps = self.config_mgr.get("rate_limit_rps", 100)
        now_sec = int(time.time())
        count, current_sec = self.rate_limits.get(client_ip, (0, now_sec))
        if current_sec == now_sec:
            if count >= max_rps:
                return False
            self.rate_limits[client_ip] = (count + 1, now_sec)
        else:
            self.rate_limits[client_ip] = (1, now_sec)
        return True

    def _udp_worker(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(4096)
                if not data:
                    continue
                threading.Thread(target=self._handle_udp_packet, args=(data, addr), daemon=True).start()
            except Exception as e:
                if not self.running:
                    break

    def _handle_udp_packet(self, data: bytes, addr: Tuple[str, int]):
        start_t = time.perf_counter()
        try:
            query = dns.message.from_wire(data)
        except Exception:
            return

        if not query.question:
            return

        q = query.question[0]
        qname = q.name.to_text().rstrip(".").lower()
        qtype = q.rdtype
        client_ip = addr[0]

        client_cfg = self.config_mgr.get_client_config(client_ip)
        client_name = client_cfg.get("name", client_ip)

        # Rate Limiting Guard
        if not self._check_rate_limit(client_ip):
            refuse_resp = dns.message.make_response(query)
            refuse_resp.set_rcode(dns.rcode.REFUSED)
            try:
                self.udp_sock.sendto(refuse_resp.to_wire(), addr)
            except Exception:
                pass
            duration_ms = round((time.perf_counter() - start_t) * 1000, 2)
            self._record_log(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), "RATE_LIMITED", duration_ms)
            self.db.log_query_async(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), "RATE_LIMITED", duration_ms)
            return

        response_wire, status = self._process_query(query, data, qname, qtype, client_ip, client_cfg)
        duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

        if response_wire:
            try:
                self.udp_sock.sendto(response_wire, addr)
            except Exception:
                pass

        self._record_log(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), status, duration_ms)
        self.db.log_query_async(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), status, duration_ms)

    def _tcp_worker(self):
        while self.running:
            try:
                client_sock, addr = self.tcp_sock.accept()
                threading.Thread(target=self._handle_tcp_conn, args=(client_sock, addr), daemon=True).start()
            except Exception:
                if not self.running:
                    break

    def _handle_tcp_conn(self, client_sock: socket.socket, addr: Tuple[str, int]):
        start_t = time.perf_counter()
        try:
            len_bytes = client_sock.recv(2)
            if len(len_bytes) < 2:
                client_sock.close()
                return
            msg_len = struct.unpack("!H", len_bytes)[0]
            data = b""
            while len(data) < msg_len:
                chunk = client_sock.recv(min(4096, msg_len - len(data)))
                if not chunk:
                    break
                data += chunk

            query = dns.message.from_wire(data)
            if query.question:
                q = query.question[0]
                qname = q.name.to_text().rstrip(".").lower()
                qtype = q.rdtype
                client_ip = addr[0]

                client_cfg = self.config_mgr.get_client_config(client_ip)
                client_name = client_cfg.get("name", client_ip)

                if not self._check_rate_limit(client_ip):
                    refuse_resp = dns.message.make_response(query)
                    refuse_resp.set_rcode(dns.rcode.REFUSED)
                    prefix = struct.pack("!H", len(refuse_resp.to_wire()))
                    client_sock.sendall(prefix + refuse_resp.to_wire())
                    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)
                    self._record_log(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), "RATE_LIMITED", duration_ms)
                    self.db.log_query_async(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), "RATE_LIMITED", duration_ms)
                    return

                response_wire, status = self._process_query(query, data, qname, qtype, client_ip, client_cfg)
                duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

                if response_wire:
                    prefix = struct.pack("!H", len(response_wire))
                    client_sock.sendall(prefix + response_wire)

                self._record_log(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), status, duration_ms)
                self.db.log_query_async(client_ip, client_name, qname, dns.rdatatype.to_text(qtype), status, duration_ms)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_query(self, query: dns.message.Message, raw_wire: bytes, qname: str, qtype: int, client_ip: str, client_cfg: dict = None) -> Tuple[Optional[bytes], str]:
        if not client_cfg:
            client_cfg = self.config_mgr.get_client_config(client_ip)

        # 1. Check Custom Local DNS Rewrites (e.g. modem.lan -> 192.168.100.1)
        rewrite_ip = self.blocklist_mgr.get_dns_rewrite(qname)
        if rewrite_ip and qtype == dns.rdatatype.A:
            resp = dns.message.make_response(query)
            abs_name = qname.rstrip(".") + "."
            rr = dns.rrset.from_text(abs_name, 300, "IN", "A", rewrite_ip)
            resp.answer.append(rr)
            return resp.to_wire(), "REWRITE"

        # 2. Check SafeSearch Enforcement (Google, Bing, DuckDuckGo, YouTube)
        safesearch_active = (
            client_cfg.get("safesearch", False) or
            client_cfg.get("profile") == "kids" or
            self.config_mgr.get("services_blocked", {}).get("safesearch", False)
        )
        if safesearch_active and qtype == dns.rdatatype.A:
            for ss_cat, ss_info in SAFESEARCH_MAPPINGS.items():
                if qname in ss_info["domains"]:
                    resp = dns.message.make_response(query)
                    abs_name = qname.rstrip(".") + "."
                    rr = dns.rrset.from_text(abs_name, 300, "IN", "A", ss_info["ip"])
                    resp.answer.append(rr)
                    return resp.to_wire(), "SAFESEARCH"

        # 3. Check if AdShield blocking is active for this client
        blocking_active = self.config_mgr.is_blocking_active()
        is_blocked = False
        block_reason = "allowed"

        if blocking_active:
            is_blocked, block_reason = self.blocklist_mgr.is_blocked_for_client(qname, client_cfg)

        if is_blocked:
            # Build Sinkhole response
            sinkhole_resp = self._make_sinkhole_response(query, qname, qtype)
            return sinkhole_resp.to_wire(), "BLOCKED"

        # 4. Check In-Memory RAM Cache
        cache_key = (qname, qtype)
        with self.cache_lock:
            if cache_key in self.cache:
                cached_wire, expire_at = self.cache[cache_key]
                if time.time() < expire_at:
                    # Replace 2-byte query ID in wire format with client's query ID
                    client_id_bytes = struct.pack("!H", query.id)
                    patched_wire = client_id_bytes + cached_wire[2:]
                    return patched_wire, "CACHED"
                else:
                    del self.cache[cache_key]

        # 5. Forward to Upstream via Parallel Fastest-Wins Race
        resp_wire, latency = self._forward_upstream(raw_wire)
        if resp_wire:
            # Store in cache & stale_cache
            try:
                resp_msg = dns.message.from_wire(resp_wire)
                min_ttl = 300
                if resp_msg.answer:
                    min_ttl = min([rr.ttl for rr in resp_msg.answer] or [300])
                min_ttl = max(self.config_mgr.get("cache_ttl_min", 60), min(min_ttl, self.config_mgr.get("cache_ttl_max", 86400)))

                with self.cache_lock:
                    self.cache[cache_key] = (resp_wire, time.time() + min_ttl)
                    self.stale_cache[cache_key] = resp_wire
            except Exception:
                pass

            return resp_wire, "FORWARDED"

        # 6. Optimistic Cache Fallback (Serve Stale if internet briefly dropped)
        if self.config_mgr.get("optimistic_cache", True):
            with self.cache_lock:
                if cache_key in self.stale_cache:
                    stale_wire = self.stale_cache[cache_key]
                    client_id_bytes = struct.pack("!H", query.id)
                    patched_wire = client_id_bytes + stale_wire[2:]
                    return patched_wire, "STALE_CACHE"

        # If upstream completely failed and no cache, return SERVFAIL
        fail_resp = dns.message.make_response(query)
        fail_resp.set_rcode(dns.rcode.SERVFAIL)
        return fail_resp.to_wire(), "ERROR"

    def _make_sinkhole_response(self, query: dns.message.Message, qname: str, qtype: int) -> dns.message.Message:
        resp = dns.message.make_response(query)
        blocking_mode = self.config_mgr.get("blocking_mode", "0.0.0.0")

        if blocking_mode == "NXDOMAIN":
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp

        # Standard IP sinkholing (0.0.0.0 for A, :: for AAAA)
        abs_name = qname.rstrip(".") + "."
        ttl = 300

        try:
            if qtype == dns.rdatatype.A:
                rr = dns.rrset.from_text(abs_name, ttl, "IN", "A", "0.0.0.0")
                resp.answer.append(rr)
            elif qtype == dns.rdatatype.AAAA:
                rr = dns.rrset.from_text(abs_name, ttl, "IN", "AAAA", "::")
                resp.answer.append(rr)
            else:
                resp.set_rcode(dns.rcode.NOERROR)
        except Exception:
            resp.set_rcode(dns.rcode.NOERROR)

        return resp

    def _forward_upstream(self, raw_wire: bytes) -> Tuple[Optional[bytes], float]:
        """
        Forward query with Parallel Fastest-Wins Race (UDP + DoH).
        If doh_only is enabled, routes strictly through encrypted DoH to defeat ISP hijacking!
        """
        start_t = time.perf_counter()
        doh_only = self.config_mgr.get("doh_only", False)
        upstreams = self.config_mgr.get("upstream_dns", ["1.1.1.1", "1.0.0.1", "8.8.8.8"])
        use_doh = self.config_mgr.get("doh_enabled", True)

        tasks = []
        if doh_only:
            # Strictly Encrypted DNS (Bypass ISP port 53 transparent proxy)
            tasks.append(("doh", "https://cloudflare-dns.com/dns-query"))
            tasks.append(("doh", "https://dns.google/dns-query"))
            tasks.append(("doh", "https://dns.quad9.net/dns-query"))
        else:
            for srv in upstreams[:3]:
                tasks.append(("udp", srv))
            if use_doh:
                tasks.append(("doh", "https://cloudflare-dns.com/dns-query"))

        result_queue = queue.Queue()

        def worker(kind, target):
            try:
                if kind == "udp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(1.8)
                    s.sendto(raw_wire, (target, 53))
                    reply, _ = s.recvfrom(4096)
                    s.close()
                    result_queue.put((target, reply))
                elif kind == "doh":
                    req = urllib.request.Request(
                        target,
                        data=raw_wire,
                        headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as res:
                        result_queue.put((target, res.read()))
            except Exception:
                pass

        threads = []
        for kind, target in tasks:
            t = threading.Thread(target=worker, args=(kind, target), daemon=True)
            t.start()
            threads.append(t)

        try:
            winner, reply = result_queue.get(timeout=2.2)
            latency = round((time.perf_counter() - start_t) * 1000, 2)
            return reply, latency
        except queue.Empty:
            pass

        return None, 0.0

    def benchmark_upstreams(self) -> list:
        """Benchmark all upstream DNS servers and DoH endpoints for latency."""
        candidates = [
            {"name": "Cloudflare DNS", "type": "UDP", "target": "1.1.1.1"},
            {"name": "Google DNS", "type": "UDP", "target": "8.8.8.8"},
            {"name": "Quad9 Secure", "type": "UDP", "target": "9.9.9.9"},
            {"name": "AdGuard DNS", "type": "UDP", "target": "94.140.14.14"},
            {"name": "Cloudflare DoH (Anti-ISP)", "type": "HTTPS (DoH)", "target": "https://cloudflare-dns.com/dns-query"},
            {"name": "Google DoH (Anti-ISP)", "type": "HTTPS (DoH)", "target": "https://dns.google/dns-query"},
            {"name": "Quad9 DoH (Anti-ISP)", "type": "HTTPS (DoH)", "target": "https://dns.quad9.net/dns-query"}
        ]

        test_msg = dns.message.make_query("google.com.", dns.rdatatype.A)
        test_wire = test_msg.to_wire()
        results = []

        for cand in candidates:
            t0 = time.perf_counter()
            success = False
            latency_ms = 999.0
            try:
                if cand["type"] == "UDP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(1.5)
                    s.sendto(test_wire, (cand["target"], 53))
                    reply, _ = s.recvfrom(4096)
                    s.close()
                    if reply:
                        success = True
                else:
                    req = urllib.request.Request(
                        cand["target"],
                        data=test_wire,
                        headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as res:
                        if res.read():
                            success = True
                if success:
                    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            except Exception:
                success = False

            results.append({
                "name": cand["name"],
                "type": cand["type"],
                "target": cand["target"],
                "latency_ms": latency_ms if success else -1,
                "status": "Online" if success else "Timeout"
            })

        results.sort(key=lambda x: x["latency_ms"] if x["latency_ms"] > 0 else 9999)
        return results

    def _record_log(self, client_ip: str, client_name: str, domain: str, qtype: str, status: str, duration_ms: float):
        now = time.strftime("%H:%M:%S")
        hour_key = time.strftime("%H:00")

        with self.log_lock:
            # Stats counters
            self.stats["total_queries"] += 1
            if status == "BLOCKED":
                self.stats["blocked_queries"] += 1
                self.top_blocked[domain] += 1
            elif status == "CACHED":
                self.stats["cached_queries"] += 1
                self.top_allowed[domain] += 1
            else:
                self.stats["forwarded_queries"] += 1
                self.top_allowed[domain] += 1

            client_label = f"{client_name} ({client_ip})" if client_name != client_ip else client_ip
            self.top_clients[client_label] += 1
            self.hourly_queries[hour_key] += 1

            # Latency average
            self.total_latency_sum += duration_ms
            self.total_latency_count += 1
            self.stats["avg_latency_ms"] = round(self.total_latency_sum / self.total_latency_count, 1)

            # Query log entry
            self.query_log.appendleft({
                "time": now,
                "client": client_ip,
                "client_name": client_name,
                "domain": domain,
                "type": qtype,
                "status": status,
                "duration": duration_ms
            })

    def _cache_cleanup_worker(self):
        """Periodically prune expired cache entries."""
        while self.running:
            time.sleep(60)
            now = time.time()
            with self.cache_lock:
                expired = [k for k, (_, exp) in self.cache.items() if now >= exp]
                for k in expired:
                    del self.cache[k]

    def clear_cache(self):
        with self.cache_lock:
            self.cache.clear()

    def get_stats_overview(self) -> dict:
        with self.log_lock:
            total = self.stats["total_queries"]
            blocked = self.stats["blocked_queries"]
            blocked_pct = round((blocked / total * 100), 1) if total > 0 else 0.0

            return {
                "total_queries": total,
                "blocked_queries": blocked,
                "cached_queries": self.stats["cached_queries"],
                "forwarded_queries": self.stats["forwarded_queries"],
                "blocked_percentage": blocked_pct,
                "avg_latency_ms": self.stats["avg_latency_ms"],
                "cache_size": len(self.cache),
                "is_blocking_active": self.config_mgr.is_blocking_active(),
                "top_blocked": self.top_blocked.most_common(5),
                "top_allowed": self.top_allowed.most_common(5),
                "top_clients": self.top_clients.most_common(5),
                "hourly_queries": dict(self.hourly_queries)
            }

    def get_query_log(self, limit: int = 100, filter_type: str = "ALL") -> list:
        with self.log_lock:
            logs = list(self.query_log)
            if filter_type == "BLOCKED":
                logs = [l for l in logs if l["status"] == "BLOCKED"]
            elif filter_type == "ALLOWED":
                logs = [l for l in logs if l["status"] in ("FORWARDED", "CACHED")]
            return logs[:limit]
