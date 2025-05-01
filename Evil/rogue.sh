#!/bin/bash

# === Evil Twin Simulation Launcher ===

# Ask for the monitor interface
while true; do
    read -rp "Enter monitor interface (e.g., wlan1mon): " IFACE
    if [[ -n "$IFACE" ]]; then
        break
    else
        echo "Interface name cannot be empty."
    fi
done

# Ask for the original AP channel
while true; do
    read -rp "Enter channel used by original AP (1–11): " ORIG_CH
    if [[ "$ORIG_CH" =~ ^[0-9]+$ ]] && (( ORIG_CH >= 1 && ORIG_CH <= 11 )); then
        break
    else
        echo "Channel must be a number between 1 and 11."
    fi
done

REAL_BSSID="BC:A5:11:DF:04:7E"   # Replace with your real AP’s BSSID
SPOOFED_BSSID="66:77:88:99:AA:BB" # Example spoofed BSSID
SSID_NAME="malmalmal"

echo ""
echo "Choose Evil Twin scenario to simulate:"
echo "  1) Exact clone (Same BSSID, Channel, WPA2-PSK/CCMP)"
echo "  2) BSSID mismatch only"
echo "  3) Channel mismatch only"
echo "  4) Auth mismatch (WPA2-PSK/TKIP)"
echo "  5) WEP Evil Twin"
echo "  6) OPEN Evil Twin (no encryption)"
echo ""

read -rp "Enter option (1–6): " MODE

# Default settings
CH="$ORIG_CH"
BSSID="$REAL_BSSID"
ENC_TAG="-Z 4"    # WPA2-PSK/CCMP
ENC_DESC="WPA2-PSK/CCMP"

case $MODE in
    1)
        # Exact clone: no changes
        ;;
    2)
        # BSSID mismatch
        BSSID="$SPOOFED_BSSID"
        ;;
    3)
        # Channel mismatch
        while true; do
            read -rp "Enter DIFFERENT channel (≠ $ORIG_CH): " CH
            if [[ "$CH" =~ ^[0-9]+$ ]] && (( CH >= 1 && CH <= 11 && CH != ORIG_CH )); then
                break
            else
                echo "Channel must be a number 1–11 and not $ORIG_CH."
            fi
        done
        ;;
    4)
        # Auth mismatch: TKIP
        ENC_TAG="-Z 2"
        ENC_DESC="WPA2-PSK/TKIP"
        ;;
    5)
        # WEP Evil Twin
        BSSID="$SPOOFED_BSSID"
        ENC_TAG="-z 1"
        ENC_DESC="WEP40"
        ;;
    6)
        # OPEN Evil Twin
        BSSID="$SPOOFED_BSSID"
        ENC_TAG="-z 0"
        ENC_DESC="OPEN (no encryption)"
        ;;
    *)
        echo "Invalid option."
        exit 1
        ;;
esac

echo ""
echo "[+] Launching Evil Twin simulation..."
echo "    SSID:       $SSID_NAME"
echo "    BSSID:      $BSSID"
echo "    Channel:    $CH"
echo "    Encryption: $ENC_DESC"
echo "    Interface:  $IFACE"
echo ""

sleep 1

# Run airbase-ng with the chosen parameters
airbase-ng -e "$SSID_NAME" -a "$BSSID" -c "$CH" $ENC_TAG "$IFACE"
