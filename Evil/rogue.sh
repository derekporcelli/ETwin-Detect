#!/bin/bash

# --- Configuration ---
PHY_IFACE="wlan1"          # Your physical wireless interface
TARGET_SSID="malmalmal" # <<< SET THE SSID YOU WANT TO BROADCAST HERE
CHANNEL=6              # Choose a channel (e.g., 1, 6, 11 for 2.4GHz)

# Network config for clients connecting to the fake AP
AT_IFACE="at0"         # Virtual interface airbase-ng usually creates
IP_ADDR="10.0.0.1"     # IP address for the AP (on at0)
NETMASK="24"           # Netmask in CIDR notation (24 = 255.255.255.0)
DHCP_RANGE="10.0.0.10,10.0.0.100,12h"
DNS_SERVER="8.8.8.8"   # DNS server for clients (e.g., Google's)

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root"
  exit 1
fi

# --- Stop interfering services ---
echo "[*] Stopping interfering services..."
# Using systemctl if available, otherwise try service command
if command -v systemctl &> /dev/null; then
    systemctl stop NetworkManager 2>/dev/null
    systemctl stop wpa_supplicant 2>/dev/null
else
    service network-manager stop 2>/dev/null
    service wpa_supplicant stop 2>/dev/null
fi
pkill airbase-ng 2>/dev/null
pkill dnsmasq 2>/dev/null
# Kill existing monitor mode interfaces just in case
airmon-ng check kill >/dev/null 2>&1

# --- Start Monitor Mode ---
echo "[*] Starting monitor mode on $PHY_IFACE..."
airmon-ng start $PHY_IFACE >/dev/null 2>&1
# Find the monitor interface name (usually adds 'mon' or similar)
# Attempt to find interface in monitor mode, robustly check common naming patterns
MON_IFACE=$(iwconfig 2>/dev/null | grep -B1 "Mode:Monitor" | head -n1 | awk '{print $1}')
if [ -z "$MON_IFACE" ]; then
    MON_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | while read iface; do \
                    iw dev "$iface" info 2>/dev/null | grep -q 'type monitor' && echo "$iface" && break; \
                done)
fi

if [ -z "$MON_IFACE" ]; then
    echo "[-] Failed to identify monitor mode interface derived from $PHY_IFACE. Check card compatibility and airmon-ng output."
    exit 1
fi
echo "[+] Monitor mode enabled on $MON_IFACE"

# --- Start airbase-ng (SSID only) ---
echo "[*] Starting airbase-ng: SSID='$TARGET_SSID' Channel=$CHANNEL (Default BSSID)"
# Use double quotes around TARGET_SSID if it contains spaces
airbase-ng -c $CHANNEL -e "$TARGET_SSID" $MON_IFACE &
AIRBASE_PID=$!
echo "[+] airbase-ng started (PID: $AIRBASE_PID). Waiting for $AT_IFACE interface..."

# Give airbase time to create the interface, check periodically
for i in {1..10}; do
    if ip link show $AT_IFACE &> /dev/null; then
        echo "[*] Interface $AT_IFACE detected."
        break
    fi
    if ! ps -p $AIRBASE_PID > /dev/null; then
        echo "[-] airbase-ng process (PID: $AIRBASE_PID) terminated prematurely. Check for errors."
        airmon-ng stop $MON_IFACE >/dev/null 2>&1
        systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null
        exit 1
    fi
    sleep 1
done

if ! ip link show $AT_IFACE &> /dev/null; then
    echo "[-] Interface $AT_IFACE was not created after 10 seconds. Check airbase output."
    kill $AIRBASE_PID 2>/dev/null
    airmon-ng stop $MON_IFACE >/dev/null 2>&1
    systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null
    exit 1
fi

# --- Configure at0 Interface ---
echo "[*] Configuring interface $AT_IFACE..."
ip link set $AT_IFACE up
ip addr flush dev $AT_IFACE
ip addr add $IP_ADDR/$NETMASK dev $AT_IFACE

# --- Start dnsmasq ---
echo "[*] Starting dnsmasq for $AT_IFACE..."
dnsmasq --interface=$AT_IFACE \
        --bind-interfaces \
        --dhcp-range=$DHCP_RANGE \
        --dhcp-option=option:router,$IP_ADDR \
        --dhcp-option=option:dns-server,$DNS_SERVER \
        --server=$DNS_SERVER \
        --log-queries \
        --log-dhcp &
DNSMASQ_PID=$!
# Check if dnsmasq started
sleep 1
if ! ps -p $DNSMASQ_PID > /dev/null; then
   echo "[-] Failed to start dnsmasq. Check configuration and logs."
   kill $AIRBASE_PID 2>/dev/null
   ip link set $AT_IFACE down 2>/dev/null
   airmon-ng stop $MON_IFACE >/dev/null 2>&1
   systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null
   exit 1
fi
echo "[+] dnsmasq started (PID: $DNSMASQ_PID)"
echo "[SUCCESS] AP '$TARGET_SSID' should be running."
echo "[INFO] Clients connect to $AT_IFACE ($IP_ADDR) using default BSSID."
echo "[!] Press Ctrl+C to stop and clean up."

# --- Cleanup Function (called on exit) ---
cleanup() {
    echo "\n[*] Cleaning up..."
    echo "[*] Stopping dnsmasq (PID: $DNSMASQ_PID)..."
    kill $DNSMASQ_PID 2>/dev/null
    echo "[*] Stopping airbase-ng (PID: $AIRBASE_PID)..."
    kill $AIRBASE_PID 2>/dev/null
    wait $AIRBASE_PID 2>/dev/null # Wait for it to exit cleanly if possible
    echo "[*] Bringing down $AT_IFACE..."
    ip link set $AT_IFACE down 2>/dev/null

    # Check if MON_IFACE exists before trying to stop it
    if ip link show $MON_IFACE &> /dev/null; then
      echo "[*] Stopping monitor mode on $MON_IFACE..."
      airmon-ng stop $MON_IFACE >/dev/null 2>&1
    else
       echo "[*] Monitor interface $MON_IFACE already gone."
    fi

    echo "[*] Restarting NetworkManager..."
    # Sometimes takes a moment for interfaces to settle
    sleep 2
    systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null
    echo "[*] Cleanup complete."
}

trap cleanup INT TERM EXIT

# Wait for airbase-ng process to prevent script ending prematurely
wait $AIRBASE_PID

# If airbase exits unexpectedly before Ctrl+C, cleanup might still run via EXIT trap
# If script ends normally after wait (e.g. airbase killed externally), cleanup runs via EXIT trap