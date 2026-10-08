# Privacy Guard Pro

Privacy Guard Pro is a desktop network auditing and monitoring tool built in Python. It analyzes local residential networks for security misconfigurations, flags exposed management interfaces on IoT hardware, and passively monitors traffic for unencrypted data leakage.

---

## Features

### Fast Network & Port Auditing
* **Subnet Discovery:** Discovers active devices on the local `/24` subnet using ARP requests.
* **Concurrent Port Scanning:** Utilizes Python's `asyncio` to probe common device management ports (HTTP, RTSP, MQTT, Smart TV services) in parallel without hanging the interface.
* **Device Identification:** Matches MAC address vendor prefixes against an internal threat and device database, extracting server identification headers from open web interfaces.

### Deep Packet Inspection (DPI)
* **DNS Query Logging:** Captures outbound DNS queries to identify external tracker domains and cloud services contacted by connected devices.
* **Cleartext Leak Detection:** Inspects local traffic on port 80 to alert users when devices transmit unencrypted HTTP request data.

### Intrusion Detection (Sentinel)
* **Gateway Pinning:** Automatically resolves and stores the router's legitimate MAC address upon startup.
* **ARP Spoof Detection:** Analyzes unsolicited ARP replies in the background to detect potential Man-in-the-Middle (MitM) cache poisoning attacks.

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
   python -m pip install customtkinter scapy requests
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

The complete Python source code is provided in `PrivacyGuardV4.py`. The application operates entirely locally and does not transmit data outside your network.

---

## License

This project is licensed under the MIT License.
