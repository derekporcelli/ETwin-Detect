#!/bin/bash

echo "=== Evil Twin Setup ==="

# Ask if we should use the same BSSID
while true; do
    read -rp "Use same BSSID as 'malmalmal'? (y/n): " SAME_BSSID
    if [[ "$SAME_BSSID" == "y" || "$SAME_BSSID" == "n" ]]; then
        break
    else
        echo "Please enter 'y' or 'n'"
    fi
done

# Ask for the channel
while true; do
    read -rp "Enter desired channel (1-11): " CHANNEL
    if [[ "$CHANNEL" =~ ^[0-9]+$ ]] && (( CHANNEL >= 1 && CHANNEL <= 11 )); then
        break
    else
        echo "Channel must be a number between 1 and 11"
    fi
done

# Simulate results
if [[ "$SAME_BSSID" == "y" ]]; then
    BSSID="BC:A5:11:DF:04:7E" 
    echo "[+] Using same BSSID: $BSSID"
else
    BSSID="66:77:88:99:AA:BB"  # Randomized or spoofed BSSID
    echo "[+] Using different BSSID: $BSSID"
fi

echo "[+] Selected Channel: $CHANNEL"

# Example placeholder for launching airbase-ng
# Replace with actual logic or commands
airbase-ng -e malmalmal -a $BSSID -c $CHANNEL wlan1mon
