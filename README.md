# ETwin-Detect
Final Version Tool is in the detector_v3 directory

This project is a wireless network monitoring tool for detecting Evil Twin and rogue access points by comparing live beacon characteristics with a known-good baseline.

##Features

- Profiling of trusted APs using `airodump-ng` + Scapy.
- Real-time monitoring with `Scapy` to detect anomalies such as:
  - Unauthorized BSSIDs
  - Channel mismatches
  - RSSI spread and deviation
  - Encryption/authentication mismatches
  - Beacon rate anomalies
- Generates structured logs (`detection_log.csv`) for post-analysis.

---

## Requirements

- **Python 3.8+**
- **Linux (Kali recommended)** with:
  - Wireless card capable of monitor mode
  - Aircrack-ng suite (`airodump-ng`, `airmon-ng`)
  - `iwconfig`, `systemctl`
- Python packages:
  ```bash
  pip install -r requirements.txt
  ```

---

## Setup

1. **Connect compatible USB WiFi adapter.**
2. **Enable monitor mode (automated by script)**.
3. **Create a trusted baseline:**
   ```bash
   sudo python3 detector_v3.py --profile
   ```
   This will:
   - Use `airodump-ng` to scan specified channels
   - Save trusted profiles to `ap_profiles_airodump.db`
   - Compute accurate beacon rate via Scapy

4. **Start monitoring:**
   ```bash
   sudo python3 detector_v3.py --monitor
   ```
   All live detections will be logged to `detection_log.csv`.

---

## Config File

`config.json` (already provided) controls the detection behavior.

```json
{
  "general": {
    "interface": "wlan0",
    "db_name": "ap_profiles_airodump.db",
    "channels_to_scan": [1, 6, 11]
  },
  "profiling": {
    "target_ssids": ["malmalmal"],
    "dwell_time_ms": 5000,
    "scan_cycles": 1
  },
  "monitoring": {
    "target_ssids": ["malmalmal"],
    "scan_dwell_seconds": 2,
    "rssi_threshold_stdev": 3.0,
    "rssi_threshold_dbm_abs": 20,
    "rssi_spread_stdev_threshold": 10.0,
    "rssi_spread_range_threshold": 25.0,
    "beacon_rate_threshold_percent": 50.0,
    "alert_cooldown_seconds": 60,
    "rssi_window_size": 20
  }
}
```

---

## Output

- `ap_profiles_airodump.db`: SQLite DB of trusted AP profiles
- `detection_log.csv`: CSV log of anomaly detections (timestamp, BSSID, reason, etc.)

---

## Validation

To validate detection:

1. Create a rogue AP using `airbase-ng` with the same SSID as the profiled AP but altered parameters (BSSID, channel, encryption, etc.).
2. Run the monitor mode.
3. Observe logged detections in `detection_log.csv`.

Example log entry:
```
timestamp,bssid,ssid,channel,rssi,reason,anomaly_type
2025-05-01 03:42:48,bc:a5:11:df:04:7e,malmalmal,1,-55,Beacon-Rate Δ 36% > 25.0%,beacon_rate
```

---

## Notes

- BSSID mismatch has detection priority. If an access point's BSSID does not match the trusted baseline, the tool will trigger an alert immediately without requiring additional validation.
- Make sure only one interface is in monitor mode during scanning to avoid conflicts.

---

## File Structure

```
├── detector_v3.py         # Main runner (profiling or monitoring)
├── monitor_logic.py       # Detection logic
├── config.json            # Detection configuration
├── detection_log.csv      # Output log file
```

## 👤 Authors

Designed and implemented by Han Chen, D'Angelo, Andy Porcelli Derek, Natarajan Pranav.
