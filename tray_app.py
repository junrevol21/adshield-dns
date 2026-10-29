"""
System Tray Application for AdShield DNS
Powered by pystray & Pillow.
"""

import threading
import time
from PIL import Image, ImageDraw

import pystray
from pystray import MenuItem as item, Menu

from windows_utils import (
    get_lan_ips, is_autostart_enabled, set_autostart,
    is_local_dns_applied, apply_local_dns, reset_local_dns,
    run_silent_cmd, launch_native_window
)

def create_shield_image(active=True, size=64):
    """Draw a crisp high-res AdGuard-style shield icon with checkmark for system tray."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = "#10b981" if active else "#f59e0b" # Vibrant Emerald if active, Amber if paused
    pts = [
        (size * 0.5, size * 0.08),
        (size * 0.88, size * 0.22),
        (size * 0.88, size * 0.58),
        (size * 0.5, size * 0.92),
        (size * 0.12, size * 0.58),
        (size * 0.12, size * 0.22)
    ]
    draw.polygon(pts, fill=color, outline="#ffffff")
    
    if active:
        # Checkmark
        c_pts = [
            (size * 0.32, size * 0.49),
            (size * 0.46, size * 0.63),
            (size * 0.70, size * 0.36)
        ]
        draw.line(c_pts, fill="#ffffff", width=max(2, int(size * 0.09)), joint="curve")
    else:
        # Two vertical pause bars
        bar_w = max(2, int(size * 0.08))
        bar_h = int(size * 0.26)
        y0 = int(size * 0.38)
        draw.rectangle([size * 0.38 - bar_w/2, y0, size * 0.38 + bar_w/2, y0 + bar_h], fill="#ffffff")
        draw.rectangle([size * 0.62 - bar_w/2, y0, size * 0.62 + bar_w/2, y0 + bar_h], fill="#ffffff")
    return img

class TrayApp:
    def __init__(self, config_mgr, blocklist_mgr, dns_engine, on_exit_callback):
        self.config_mgr = config_mgr
        self.blocklist_mgr = blocklist_mgr
        self.dns_engine = dns_engine
        self.on_exit_callback = on_exit_callback
        self.icon = None

    def open_dashboard(self):
        port = self.config_mgr.get("web_port", 5380)
        launch_native_window(f"http://localhost:{port}")

    def pause_blocking(self, minutes: int):
        if minutes > 0:
            self.config_mgr.pause_blocking(minutes * 60)
        else:
            self.config_mgr.pause_blocking(0)
        self.update_icon_state()

    def resume_blocking(self):
        self.config_mgr.resume_blocking()
        self.update_icon_state()

    def copy_lan_ip(self):
        ips = get_lan_ips()
        ip_str = ips[0] if ips else "127.0.0.1"
        try:
            run_silent_cmd(f'echo | set /p="{ip_str}" | clip')
            if self.icon:
                self.icon.notify(f"DNS IP ({ip_str}) copied to clipboard!", "AdShield DNS")
        except Exception:
            pass

    def trigger_blocklist_update(self):
        if self.blocklist_mgr.update_blocklists_async():
            if self.icon:
                self.icon.notify("Blocklist update started in background.", "AdShield DNS")

    def toggle_autostart(self):
        current = is_autostart_enabled()
        set_autostart(not current)

    def toggle_local_dns(self):
        if is_local_dns_applied():
            reset_local_dns()
            if self.icon:
                self.icon.notify("PC DNS restored to DHCP default.", "AdShield DNS")
        else:
            apply_local_dns()
            if self.icon:
                self.icon.notify("AdShield DNS protection active on this PC!", "AdShield DNS")

    def update_icon_state(self):
        if self.icon:
            active = self.config_mgr.is_blocking_active()
            self.icon.icon = create_shield_image(active=active)
            status_text = "Protection Active" if active else "Protection Paused"
            self.icon.title = f"AdShield DNS - {status_text}"

    def build_menu(self):
        active = self.config_mgr.is_blocking_active()
        status_label = "● Status: Active (Blocking)" if active else "● Status: Paused"

        menu = Menu(
            item("🛡️ Open Dashboard", lambda: self.open_dashboard(), default=True),
            item(status_label, lambda: None, enabled=False),
            Menu.SEPARATOR,
            item("⏸️ Pause Protection", Menu(
                item("⏱️ 5 Minutes", lambda: self.pause_blocking(5)),
                item("⏱️ 15 Minutes", lambda: self.pause_blocking(15)),
                item("⏱️ 1 Hour", lambda: self.pause_blocking(60)),
                item("⏸️ Until Resumed", lambda: self.pause_blocking(0))
            )),
            item("▶️ Resume Protection", lambda: self.resume_blocking()),
            Menu.SEPARATOR,
            item("📋 Copy Local DNS IP", lambda: self.copy_lan_ip()),
            item("💻 Protect This PC (Local DNS)", lambda: self.toggle_local_dns(), checked=lambda _: is_local_dns_applied()),
            item("🔄 Update Blocklists", lambda: self.trigger_blocklist_update()),
            item("⚡ Start on Windows Boot", lambda: self.toggle_autostart(), checked=lambda _: is_autostart_enabled()),
            Menu.SEPARATOR,
            item("❌ Exit AdShield", lambda: self.exit_app())
        )
        return menu

    def exit_app(self):
        if self.icon:
            self.icon.stop()
        if self.on_exit_callback:
            self.on_exit_callback()

    def _setup_tray(self, icon):
        icon.visible = True
        try:
            icon.notify(
                "AdShield DNS is running in the background. Right-click this shield icon anytime to control.",
                "AdShield DNS Active"
            )
        except Exception:
            pass

        # Periodic status refresh
        def refresh_loop():
            while icon and icon.visible:
                time.sleep(4)
                try:
                    self.update_icon_state()
                    icon.menu = self.build_menu()
                except Exception:
                    pass

        threading.Thread(target=refresh_loop, daemon=True).start()

    def run(self):
        image = create_shield_image(active=self.config_mgr.is_blocking_active())
        self.icon = pystray.Icon("AdShieldDNS", image, "AdShield DNS - Universal AdBlocker", menu=self.build_menu())
        print("[TrayApp] Starting system tray icon...")
        self.icon.run(setup=self._setup_tray)
