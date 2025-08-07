# Suspicious Traffic Alerter for macOS

This script monitors your network traffic for suspicious activity and sends a native macOS notification if it finds anything. It detects connections to known malicious IPs and potential port scanning attempts. Great for personal setups and apartment buildings.

## Description

- Malicious IP Detection: Downloads a list of known malicious IP addresses from the Feodo Tracker (abuse.ch) and checks if any incoming or outgoing traffic communicates with these IPs.
- Port Scan Detection: Monitors for potential port scanning activity by tracking the number of connection attempts from a single external source to multiple ports on your machine within a short timeframe.
- macOS Notifications: Displays native notifications with details about suspicious events.

**Security:**  
The script automatically checks for root privileges and re-executes itself with `sudo` if necessary. This ensures proper permissions for packet sniffing. Use with care, as root privileges are required.

## Requirements

- Python 3
- Third-party libraries:
  - `scapy` (network packet sniffing)
  - `macos-notifications` (native macOS notifications)
  - `requests` (downloading the IP blocklist)
- Standard libraries:
  - `os`, `sys`, `time`, `collections`, `ipaddress`

## Installation

Install dependencies using pip:

```sh
pip3 install scapy macos-notifications requests
```

## Usage

1. Save the script as `traffic_monitor_MACOS.py`.
2. Make it executable:
   ```sh
   chmod +x traffic_monitor_MACOS.py
   ```
3. Run it (no need to manually use sudo; the script will prompt and re-execute itself with sudo if needed):
   ```sh
   ./traffic_monitor_MACOS.py
   ```
   or
   ```sh
   python3 traffic_monitor_MACOS.py
   ```

Press `Ctrl+C` to stop monitoring.

## Notes

- The script ignores traffic from private/local IP addresses when detecting port scans.
- If the blocklist cannot be downloaded, the script will continue running but will not check for malicious IPs.
- Notifications are sent only once per suspicious event per timeframe to avoid spamming.
- All network monitoring and notification logic is wrapped in a single main execution block for reliability.
- The script is robust against missing dependencies and will print errors if notifications or blocklist downloads fail.

## License

MIT License.
