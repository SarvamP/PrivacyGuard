# Privacy Guard Pro

Privacy Guard Pro is a desktop network auditing and monitoring tool built in Python. It analyzes local residential networks for security misconfigurations, flags exposed management interfaces on IoT hardware, and passively monitors traffic for unencrypted data leakage.

---

## Features

### Fast Network & Port Auditing
* **Subnet Discovery:** Discovers active devices on the directly connected IPv4 subnet of the default network adapter (up to 1,024 addresses) using ARP requests.
* **Concurrent Port Scanning:** Utilizes Python's `asyncio` to probe common device management ports (HTTP, RTSP, MQTT, Smart TV services) in parallel without hanging the interface.
* **Device Identification:** Matches MAC address vendor prefixes against Scapy’s bundled manufacturer database, extracting server identification headers from open web interfaces.

### Deep Packet Inspection (DPI)
* **DNS Query Logging:** Logs visible IPv4 DNS queries. Encrypted DNS traffic is outside this feature’s coverage.
* **Cleartext Leak Detection:** Flags visible IPv4 HTTP GET and POST request lines on TCP port 80 when they appear at the start of a captured packet.

### Intrusion Detection (Sentinel)
* **Gateway Pinning:** Records the gateway MAC reported by ARP when Sentinel is enabled and uses it as a baseline.
* **ARP Spoof Detection:** Flags observed ARP replies that claim the gateway IP with a different MAC address. A change is an alert to investigate.

Capture is limited to traffic visible on the default IPv4 adapter. On typical switched Ethernet and Wi-Fi, this usually excludes other devices’ unicast traffic. Sentinel requires an IPv4 gateway and working Npcap access on Windows.

### Modern Interface
* Built with `customtkinter` to provide a native dark-mode interface with tabbed views for auditing, live traffic analysis, and security alerts.

---

## Download & Installation

### Option 1: Standalone Windows App
1. Go to the **Releases** tab on the right side of this repository.
2. Download `PrivacyGuardV4.exe`.
3. Right-click the `.exe` and select **Run as Administrator** (required for raw packet socket access on Windows).

### Option 2: Running from Source

#### Prerequisites
* Python 3.10 or higher
* Npcap installed with "WinPcap API-compatible mode" enabled (required for Scapy packet capture on Windows)

#### Setup
1. Clone or download this repository.
2. Install the required dependencies:
   ```bash
   python -m pip install customtkinter scapy==2.7.0
   ```
3. Run the application:
   ```bash
   python PrivacyGuardV4.py
   ```

---

## Antivirus False-Positive Notice

Security software like Windows Defender may flag the standalone executable. This occurs for two standard reasons:

1. **PyInstaller Packaging:** The executable is bundled into a single file with an embedded Python interpreter, a packaging format frequently flagged by heuristic scanners.
2. **Raw Packet Capture:** The application sends raw Layer-2 ARP frames and monitors local interface packets via Scapy, which behavioral analysis tools flag as network-monitoring behavior.

The complete Python source code is provided in `PrivacyGuardV4.py`. The current source uses a bundled database for vendor lookups and does not send device identifiers or captured traffic to a third-party service. Use the source installation steps to get these changes until a standalone build from this revision is available.

---
<img width="1851" height="762" alt="image" src="https://github.com/user-attachments/assets/6dd7452a-71b0-4aca-b2b4-fdba4e379cef" />


## License

This project is licensed under the MIT License.
