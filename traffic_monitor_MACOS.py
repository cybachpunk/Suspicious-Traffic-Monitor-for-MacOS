#!/usr/bin/env python3
#
# Suspicious Traffic Alerter for macOS
#
# This script monitors your network traffic for suspicious activity and
# sends a native macOS notification if it finds anything.
#
# Author: Gemini
# Version: 1.0.0
#
# --- DESCRIPTION ---
# This script performs two main checks:
# 1.  It downloads a list of known malicious IP addresses from a public
#     blocklist (abuse.ch Feodo Tracker) and checks if any incoming or
#     outgoing traffic is communicating with these IPs.
# 2.  It monitors for potential port scanning activity by tracking the number
#     of connection attempts from a single source to multiple ports on your
#     machine.
#
# When suspicious activity is detected, a native macOS notification is
# displayed with details about the event.
#
# --- REQUIREMENTS ---
# This script requires Python 3 and the following third-party libraries:
# - scapy: For sniffing and analyzing network packets.
# - macos-notifications: For sending native macOS notifications.
# - requests: For downloading the IP blocklist.
#
# You can install these with pip:
# pip3 install scapy macos-notifications requests
#
# --- USAGE ---
# This script must be run with root privileges to capture network traffic.
#
# 1.  Save the script as a Python file (e.g., `traffic_alerter.py`).
# 2.  Make it executable: `chmod +x traffic_alerter.py`
# 3.  Run it with sudo: `sudo ./traffic_alerter.py`
#
# To stop the script, press Ctrl+C in the terminal where it's running.
#

import requests
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from mac_notifications import client

# --- CONFIGURATION ---

# URL for the Feodo Tracker IP blocklist. This is a reputable source for
# identifying botnet command and control (C&C) servers.
BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# Port scanning detection parameters
PORT_SCAN_THRESHOLD = 15  # Number of different ports scanned to trigger an alert
PORT_SCAN_TIMEFRAME = 60  # Timeframe in seconds to monitor for port scans

# --- GLOBAL VARIABLES ---

# Set to store the malicious IP addresses
malicious_ips = set()

# Dictionary to track potential port scans.
# Structure: {scanner_ip: {'ports': {port1, port2, ...}, 'timestamp': float}}
port_scan_trackers = defaultdict(lambda: {'ports': set(), 'timestamp': 0.0})


def download_blocklist():
    """
    Downloads the IP blocklist from the configured URL and loads it into memory.
    """
    global malicious_ips
    print("[+] Downloading malicious IP blocklist...")
    try:
        response = requests.get(BLOCKLIST_URL)
        response.raise_for_status()  # Raise an exception for bad status codes

        lines = response.text.splitlines()
        # Filter out comments and empty lines
        ips = {line.strip() for line in lines if not line.startswith("#") and line.strip()}
        
        if not ips:
            print("[-] Warning: The downloaded blocklist is empty.")
            return

        malicious_ips = ips
        print(f"[+] Successfully downloaded and loaded {len(malicious_ips)} malicious IP addresses.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error downloading blocklist: {e}")
        print("[-] The script will continue without checking against the blocklist.")


def send_notification(title, subtitle, message):
    """
    Sends a native macOS notification.
    """
    try:
        client.create_notification(
            title=title,
            subtitle=subtitle,
            text=message,
            sound="Basso"
        )
        print(f"[!] Notification sent: {title} - {subtitle}")
    except Exception as e:
        print(f"[-] Failed to send notification: {e}")


def check_for_port_scan(packet):
    """
    Analyzes incoming TCP packets to detect potential port scanning.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    # We only care about incoming packets to our machine for port scans
    # so we can ignore packets originating from ourself.
    # Note: This is a simplification. In a real scenario, you'd get your
    # own IP address instead of hardcoding localhost.
    if src_ip == "127.0.0.1":
        return

    current_time = time.time()
    tracker = port_scan_trackers[src_ip]

    # Reset tracker if the last scan attempt was outside the timeframe
    if current_time - tracker['timestamp'] > PORT_SCAN_TIMEFRAME:
        tracker['ports'] = {dst_port}
        tracker['timestamp'] = current_time
    else:
        tracker['ports'].add(dst_port)

    # Check if the number of scanned ports exceeds the threshold
    if len(tracker['ports']) > PORT_SCAN_THRESHOLD:
        # To avoid spamming notifications, we only alert once per timeframe
        if len(tracker['ports']) == PORT_SCAN_THRESHOLD + 1:
             send_notification(
                "🚨 Potential Port Scan Detected!",
                f"From IP: {src_ip}",
                f"Scanned {len(tracker['ports'])} ports in {PORT_SCAN_TIMEFRAME} seconds."
            )

def packet_callback(packet):
    """
    This function is called for each packet captured by Scapy.
    """
    # Check for connection to/from malicious IPs
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in malicious_ips:
            send_notification(
                "🚨 Malicious IP Detected!",
                f"Source: {src_ip}",
                f"Your Mac made a connection to a known malicious IP address."
            )
        elif dst_ip in malicious_ips:
            send_notification(
                "🚨 Malicious IP Detected!",
                f"Destination: {dst_ip}",
                f"A known malicious IP address tried to connect to your Mac."
            )

    # Check for port scanning activity
    check_for_port_scan(packet)


if __name__ == "__main__":
    print("--- Suspicious Traffic Alerter for macOS ---")
    print("Starting up...")
    
    # Download the initial blocklist
    download_blocklist()
    
    print("\n[+] Starting network traffic monitoring...")
    print("Press Ctrl+C to stop.")

    try:
        # Start sniffing packets. The `prn` argument specifies the callback
        # function to be called for each packet. `store=0` tells Scapy not to
        # store the packets in memory, which is more efficient for long-running
        # captures.
        sniff(prn=packet_callback, store=0)
    except PermissionError:
        print("\n[-] Error: This script requires root privileges to capture network traffic.")
        print("[-] Please run it with 'sudo'.")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
    finally:
        print("\n[+] Stopping traffic monitoring. Goodbye!")

