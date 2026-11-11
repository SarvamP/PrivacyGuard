import scapy.all as scapy
import requests
import time
import socket
import threading
import asyncio
import customtkinter as ctk
from datetime import datetime

# =======================================================
#               THREAT INTELLIGENCE DATABASE
# =======================================================
def load_vulnerability_database():
    return {
      "Netgear": {"device_type": "Network Router", "privacy_risk": "Legacy router firmware exposes HTTP port 80.", "action_item": "Disable 'Remote Management' in settings."},
      "Linksys": {"device_type": "Network Router", "privacy_risk": "Older models broadcast network layout via SNMP.", "action_item": "Access Smart Wi-Fi dashboard and update firmware."},
      "TP-Link": {"device_type": "Router / Smart Plug", "privacy_risk": "Smart plugs communicate using unencrypted JSON data.", "action_item": "Use mobile app to bind devices strictly to your account."},
      "Asus": {"device_type": "Gaming Router", "privacy_risk": "Leaves UPnP active by default, exposing network ports.", "action_item": "Navigate to WAN settings and turn off UPnP."},
      "Ubiquiti": {"device_type": "Access Point / Switch", "privacy_risk": "Can expose SSH management interfaces if unconfigured.", "action_item": "Ensure UniFi Network Controller has device SSH authentication enabled."},
      "Synology": {"device_type": "Network Attached Storage", "privacy_risk": "NAS systems can be targeted via local brute-force attacks.", "action_item": "Enable Auto-Block in DSM Settings to ban failed IP addresses."},
      "Ring": {"device_type": "Security Camera", "privacy_risk": "Video devices communicate constantly with cloud servers via web sockets.", "action_item": "Enable Two-Factor Authentication (2FA) in the Ring app."},
      "Nest": {"device_type": "Smart Thermostat / Cam", "privacy_risk": "Nest tracks environmental telemetry and local ambient temperatures.", "action_item": "Review Google Home account privacy controls to manage data history."},
      "Apple": {"device_type": "MacBook / iPad / iPhone", "privacy_risk": "Exposes structural discovery ports for AirPlay and AirDrop.", "action_item": "Verify that AirPlay and discovery permissions are set safely."},
      "Microsoft": {"device_type": "Windows PC / Xbox", "privacy_risk": "Shares local diagnostic data and active peer update packets.", "action_item": "Turn off local PC Delivery Optimization in Windows Update settings."},
      "Google": {"device_type": "Smart Home / Mesh Node", "privacy_risk": "Hubs stream massive amounts of local telemetry cache data.", "action_item": "Isolate all smart home hubs onto a dedicated 'Guest' Wi-Fi band."},
      "Unknown Device": {"device_type": "Mobile Device / Randomized MAC", "privacy_risk": "Utilizing MAC address randomization or hiding its hostname.", "action_item": "Verify this hardware MAC matches a known family smartphone."}
    }

# =======================================================
#         ENGINE 1: ASYNCHRONOUS PORT SCANNER
# =======================================================
TARGET_PORTS = {
    80: "HTTP (Web Admin)", 443: "HTTPS (Secure Web)", 
    554: "RTSP (Camera Stream)", 1883: "MQTT (IoT Broker)",
    8008: "HTTP Alt (Cast/TV)", 8080: "HTTP Proxy/Admin"
}

async def check_port_async(ip, port, timeout=0.6):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        banner_str = ""
        if port in [80, 8080, 8008]:
            try:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(256), timeout=timeout)
                for line in response.decode(errors="ignore").splitlines():
                    if line.lower().startswith("server:"):
                        banner_str = f" [{line.strip()}]"
                        break
            except: pass
        writer.close()
        return port, banner_str
    except:
        return port, None

async def probe_device_services_async(ip):
    discovered = []
    tasks = [check_port_async(ip, port) for port in TARGET_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    for port, banner in results:
        if banner is not None:
            discovered.append(f"Port {port} - {TARGET_PORTS[port]}{banner}")
    return discovered

# =======================================================
#         ENGINE 2 & 3: DPI & IDS SENTINEL THREAD
# =======================================================
class BackgroundSentinel:
    def __init__(self, app):
        self.app = app
        self.gateway_ip = app.gateway_ip
        self.gateway_mac = None
        self.running = False

    def get_mac(self, ip):
        try:
            ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=0)
            if ans: return ans[0][1].hwsrc
        except: pass
        return None

    def start(self):
        self.running = True
        self.app.log_ids(f"[*] Initializing Sentinel IDS on gateway: {self.gateway_ip}...", "system")
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        if self.gateway_mac:
            self.app.log_ids(f"[+] Gateway MAC securely pinned: {self.gateway_mac}", "complete")
        else:
            self.app.log_ids(f"[!] Warning: Could not resolve Gateway MAC. ARP monitoring limited.", "ports")
        
        self.app.log_dpi(f"[*] Live Deep Packet Inspection (DPI) listening for DNS and Cleartext TCP leaks...", "system")
        threading.Thread(target=self.sniff_loop, daemon=True).start()

    def stop(self):
        self.running = False
        self.app.log_dpi(f"[*] Sentinel deactivated.", "system")
        self.app.log_ids(f"[*] Sentinel deactivated.", "system")

    def sniff_loop(self):
        try:
            scapy.sniff(store=False, prn=self.process_packet, stop_filter=lambda x: not self.running)
        except Exception as e:
            pass

    def process_packet(self, pkt):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
            src_ip = pkt[scapy.ARP].psrc
            src_mac = pkt[scapy.ARP].hwsrc
            if src_ip == self.gateway_ip and self.gateway_mac:
                if src_mac != self.gateway_mac:
                    msg = f"[{timestamp}] 🚨 INTRUSION ALERT! Gateway IP {src_ip} claimed by Rogue MAC: {src_mac}"
                    self.app.root.after(0, self.app.log_ids, msg, "alert")
        
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
            qname = pkt[scapy.DNS].qd.qname.decode(errors='ignore').strip('.')
            if pkt.haslayer(scapy.IP):
                msg = f"[{timestamp}] 🌐 DNS Query: {pkt[scapy.IP].src} requested {qname}"
                self.app.root.after(0, self.app.log_dpi, msg, "dns")
                
        if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].dport == 80 and pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load.decode(errors='ignore')
            if payload.startswith("GET ") or payload.startswith("POST "):
                if pkt.haslayer(scapy.IP):
                    req_line = payload.split('\r\n')[0]
                    msg = f"[{timestamp}] ⚠️ CLEARTEXT LEAK: {pkt[scapy.IP].src} sent {req_line}"
                    self.app.root.after(0, self.app.log_dpi, msg, "leak")

# =======================================================
#               CORE UTILITIES & GUI
# =======================================================
def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
        if response.status_code == 200: return response.text
    except: pass
    return "Unknown Device"

def auto_detect_network_range():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        ip_pieces = local_ip.split(".")
        return f"{ip_pieces[0]}.{ip_pieces[1]}.{ip_pieces[2]}.1/24", local_ip, f"{ip_pieces[0]}.{ip_pieces[1]}.{ip_pieces[2]}.1"
    except:
        return "192.168.1.1/24", "Unknown", "192.168.1.1"

class PrivacyScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Privacy Guard Pro")
        self.root.geometry("950x750")
        self.root.minsize(800, 600)
        
        # Configure modern window
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.vuln_db = load_vulnerability_database()
        self.net_range, self.local_ip, self.gateway_ip = auto_detect_network_range()
        self.sentinel = BackgroundSentinel(self)
        
        self.setup_ui()
        
    def setup_ui(self):
        # 1. Top Control Card (Rounded)
        top_frame = ctk.CTkFrame(self.root, corner_radius=15)
        top_frame.pack(fill=ctk.X, padx=20, pady=(20, 10))
        
        # Modern UI Controls
        self.scan_button = ctk.CTkButton(top_frame, text="RUN NETWORK AUDIT", font=("Segoe UI", 13, "bold"),
                                         width=180, height=45, corner_radius=8,
                                         command=self.start_scan_thread)
        self.scan_button.pack(side=ctk.LEFT, padx=20, pady=20)
        
        self.sentinel_switch = ctk.CTkSwitch(top_frame, text="Enable IDS Sentinel", font=("Segoe UI", 13, "bold"),
                                             progress_color="#8a2BE2", command=self.toggle_sentinel)
        self.sentinel_switch.pack(side=ctk.LEFT, padx=10, pady=20)
        
        # Dynamic Labels
        stats_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        stats_frame.pack(side=ctk.RIGHT, padx=20, pady=15)
        
        ctk.CTkLabel(stats_frame, text="TARGET SUBNET", font=("Segoe UI", 10, "bold"), text_color="gray").pack(anchor="e")
        ctk.CTkLabel(stats_frame, text=self.net_range, font=("Segoe UI", 16, "bold"), text_color="#58A6FF").pack(anchor="e")

        # 2. Sleek Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.root, mode="indeterminate", height=4, corner_radius=0)
        self.progress_bar.pack(fill=ctk.X, padx=20, pady=5)
        self.progress_bar.set(0)

        # 3. Modern Tabbed View
        self.tabview = ctk.CTkTabview(self.root, corner_radius=10)
        self.tabview.pack(fill=ctk.BOTH, expand=True, padx=20, pady=(5, 20))
        
        tab_scanner = self.tabview.add("🛡️ Network Auditor")
        tab_dpi = self.tabview.add("👁️ Live DPI Engine")
        tab_ids = self.tabview.add("🚨 IDS Sentinel")
        
        # Rounded Textboxes
        self.display_area = self.create_text_area(tab_scanner)
        self.dpi_area = self.create_text_area(tab_dpi, font=("Consolas", 12))
        self.ids_area = self.create_text_area(tab_ids, font=("Consolas", 12))
        
        # Color Tags (Hooking into internal tkinter text widget)
        self.setup_tags(self.display_area)
        self.setup_tags(self.dpi_area)
        self.setup_tags(self.ids_area)

        self.log_scan("System initialized. Click 'RUN NETWORK AUDIT' to map local devices.", "system")
        self.log_dpi("Awaiting Sentinel activation...", "system")
        self.log_ids("Awaiting Sentinel activation...", "system")

    def create_text_area(self, parent, font=("Segoe UI Semibold", 13)):
        area = ctk.CTkTextbox(parent, wrap="word", font=font, corner_radius=8, fg_color="#161B22", text_color="#C9D1D9")
        area.pack(fill=ctk.BOTH, expand=True, padx=5, pady=5)
        area.configure(state="disabled")
        return area

    def setup_tags(self, ctk_textbox):
        # CTkTextbox wraps a standard tkinter Text widget, we apply tags directly to it
        inner_txt = ctk_textbox._textbox
        inner_txt.tag_config("system", foreground="#8B949E", font=("Segoe UI Italic", 12))
        inner_txt.tag_config("device_header", foreground="#58A6FF", font=("Segoe UI", 14, "bold"))
        inner_txt.tag_config("label", foreground="#8B949E", font=("Segoe UI", 12, "bold"))
        inner_txt.tag_config("value", foreground="#ECEFF4", font=("Segoe UI", 12))
        inner_txt.tag_config("ports", foreground="#D29922", font=("Segoe UI Semibold", 12))
        inner_txt.tag_config("complete", foreground="#3FB950", font=("Segoe UI", 13, "bold"))
        inner_txt.tag_config("dns", foreground="#C9D1D9")
        inner_txt.tag_config("leak", foreground="#F85149", font=("Consolas", 12, "bold"))
        inner_txt.tag_config("alert", foreground="#F85149", font=("Consolas", 13, "bold"))

    def _log_to_area(self, text_widget, message, tag=None):
        text_widget.configure(state="normal")
        if tag: text_widget.insert("end", message + "\n", tag)
        else: text_widget.insert("end", message + "\n")
        text_widget.see("end")
        text_widget.configure(state="disabled")

    def log_scan(self, msg, tag=None): self._log_to_area(self.display_area, msg, tag)
    def log_dpi(self, msg, tag=None): self._log_to_area(self.dpi_area, msg, tag)
    def log_ids(self, msg, tag=None): self._log_to_area(self.ids_area, msg, tag)

    def toggle_sentinel(self):
        if self.sentinel_switch.get() == 1:
            self.sentinel.start()
        else:
            self.sentinel.stop()

    def start_scan_thread(self):
        self.scan_button.configure(state="disabled", text="SCANNING...")
        self.progress_bar.start()
        self.display_area.configure(state="normal")
        self.display_area.delete("1.0", "end")
        self.display_area.configure(state="disabled")
        threading.Thread(target=self.run_network_audit, daemon=True).start()

    def run_network_audit(self):
        self.log_scan("⚙️ Map Phase: Sweeping network neighborhood via ARP broadcasts...", "system")
        try:
            ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.net_range), timeout=3, verbose=False)[0]
            self.log_scan(f"🔎 Reconnaissance Phase: Concurrent Async Probing {len(ans)} devices...\n", "system")
            self.log_scan("=" * 65 + "\n", "system")
            
            for element in ans:
                ip = element[1].psrc
                mac = element[1].hwsrc
                vendor = get_vendor(mac)
                open_services = asyncio.run(probe_device_services_async(ip))
                
                audit = {"device_type": "Generic Device", "privacy_risk": "No custom risk data.", "action_item": "Ensure strong custom passwords."}
                for key in self.vuln_db:
                    if key.lower() in vendor.lower():
                        audit = self.vuln_db[key]
                        break
                
                self.log_scan(f"📱 {vendor} ({ip})", "device_header")
                self.log_scan("    Category:    ", "label")
                self._log_to_area(self.display_area, f"{audit['device_type']}", "value")
                
                self.log_scan("    Open Ports:  ", "label")
                if open_services:
                    self._log_to_area(self.display_area, f"{' | '.join(open_services)}", "ports")
                else:
                    self._log_to_area(self.display_area, "No common management ports exposed", "value")
                
                self.log_scan("    Privacy:     ", "label")
                self._log_to_area(self.display_area, f"{audit['privacy_risk']}", "value")
                self.log_scan("    Fix Item:    ", "label")
                self._log_to_area(self.display_area, f"{audit['action_item']}\n", "value")
                
            self.log_scan("=" * 65 + "\n", "system")
            self.log_scan("✨ Audit complete. Review the steps above to fortify your local network.", "complete")
        except Exception as error:
            self.log_scan(f"\n🛑 Audit process execution breakdown: {str(error)}", "alert")
        finally:
            self.progress_bar.stop()
            self.progress_bar.set(0)
            self.scan_button.configure(state="normal", text="RUN NETWORK AUDIT")

if __name__ == "__main__":
    root_window = ctk.CTk()
    app = PrivacyScannerApp(root_window)
    root_window.mainloop()