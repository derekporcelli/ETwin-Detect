#!/usr/bin/env python3

import argparse
import datetime
import glob
import json
import os
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import time
import pandas as pd
from collections import defaultdict
import dector_v3.monitor_logic as monitor_logic
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp

# --- Configuration Loading ---
CONFIG_DEFAULTS = {
    "general": {
        "interface": "wlan0",
        "db_name": "ap_profiles_airodump.db",
        "channels_to_scan": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        "temp_dir": "/tmp/airodump_profiling",
    },
    "profiling": {
        "dwell_time_ms": 5000,
        "scan_cycles": 1,
        "target_ssids": ["malmalmal"],
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
        "rssi_window_size": 20,
    },
}


def load_config(filepath):
    """
    Loads configuration from a JSON file and merges it with defaults.
    Exits on error.
    """
    try:
        with open(filepath, "r") as f:
            config_from_file = json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file '{filepath}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Could not parse config '{filepath}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    # Merge defaults and file values
    merged = {}
    for section, defaults in CONFIG_DEFAULTS.items():
        if section in config_from_file:
            value = config_from_file[section]
            if isinstance(value, dict):
                merged_section = defaults.copy()
                merged_section.update(value)
                merged[section] = merged_section
            else:
                merged[section] = value
        else:
            merged[section] = defaults

    print(f"Configuration loaded from '{filepath}'")

    # Validate required fields
    profiling = merged["profiling"]
    general = merged["general"]

    if not profiling["target_ssids"]:
        print("Error: 'profiling.target_ssids' cannot be empty.")
        sys.exit(1)

    if not general["channels_to_scan"]:
        print("Error: 'general.channels_to_scan' cannot be empty.")
        sys.exit(1)

    if profiling["dwell_time_ms"] <= 0:
        print("Error: 'profiling.dwell_time_ms' must be positive.")
        sys.exit(1)

    if profiling["scan_cycles"] <= 0:
        print("Error: 'profiling.scan_cycles' must be positive.")
        sys.exit(1)

    return merged


# Global configuration placeholder
config = None


def set_monitor_mode(iface, enable=True):
    """
    Enables or disables monitor mode on the given interface.
    Returns the new interface name on success, or None on failure.
    """
    try:
        subprocess.run(["which", "airmon-ng"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: 'airmon-ng' not found; install aircrack-ng suite.")
        return None

    if enable:
        print(f"Enabling monitor mode on {iface}...")
        try:
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                check=True,
                capture_output=True,
                timeout=15,
            )
            result = subprocess.run(
                ["airmon-ng", "start", iface],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.CalledProcessError as e:
            print(f"Error enabling monitor mode: {e.stderr}")
            return None
        except subprocess.TimeoutExpired:
            print("Error: airmon-ng start command timed out.")
            return None

        monitor_iface = f"{iface}mon"
        print(f"Monitor interface is {monitor_iface}")
        return monitor_iface

    else:
        print(f"Disabling monitor mode on {iface}...")
        try:
            subprocess.run(
                ["airmon-ng", "stop", iface],
                check=False,
                capture_output=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            print("Warning: airmon-ng stop command timed out.")

        try:
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                check=False,
                capture_output=True,
                timeout=15,
            )
        except Exception:
            print("Warning: could not restart NetworkManager.")

        return iface


def init_db():
    """
    Creates (if needed) the SQLite database and whitelist table.
    """
    db_path = config["general"]["db_name"]
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS whitelist (
            ssid TEXT NOT NULL,
            bssid TEXT PRIMARY KEY NOT NULL,
            channel INTEGER,
            avg_rssi REAL,
            stddev_rssi REAL,
            privacy_raw TEXT,
            cipher_raw TEXT,
            authentication_raw TEXT,
            avg_beacon_rate REAL,
            profiled_time TEXT NOT NULL
        );
        """
    )

    conn.commit()
    conn.close()

    print(f"Database '{db_path}' initialized.")


def add_to_whitelist(profile_data):
    """
    Inserts or replaces an AP profile into the whitelist table.
    """
    db_path = config["general"]["db_name"]
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO whitelist (
            ssid, bssid, channel, avg_rssi, stddev_rssi,
            privacy_raw, cipher_raw, authentication_raw,
            avg_beacon_rate, profiled_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            profile_data["ssid"],
            profile_data["bssid"].lower(),
            profile_data["channel"],
            profile_data["avg_rssi"],
            profile_data["stddev_rssi"],
            profile_data["privacy_raw"],
            profile_data["cipher_raw"],
            profile_data["authentication_raw"],
            profile_data["avg_beacon_rate"],
            profile_data["profiled_time"],
        ),
    )

    conn.commit()
    conn.close()


def parse_auth_details(privacy_set, cipher_set, auth_set):
    """
    Determines standardized auth_type and cipher from raw fields.
    """
    base_type = "Unknown"

    if "OWE" in auth_set:
        base_type = "OWE"
    elif "WPA3" in privacy_set:
        base_type = "WPA3"
    elif "WPA2" in privacy_set:
        base_type = "WPA2"
    elif "WPA" in privacy_set:
        base_type = "WPA"
    elif "WEP" in privacy_set:
        base_type = "WEP"
    elif "OPN" in privacy_set:
        base_type = "OPEN"

    final_auth = base_type

    if base_type == "WPA3" and "SAE" in auth_set:
        final_auth += "-SAE"
    elif base_type in ("WPA2", "WPA"):
        if "PSK" in auth_set:
            final_auth += "-PSK"
        elif "MGT" in auth_set:
            final_auth += "-EAP"

    final_cipher = "Unknown"

    if "GCMP-256" in cipher_set:
        final_cipher = "GCMP-256"
    elif "GCMP-128" in cipher_set:
        final_cipher = "GCMP-128"
    elif "CCMP" in cipher_set:
        final_cipher = "CCMP"
    elif "TKIP" in cipher_set:
        final_cipher = "TKIP"
    elif "WEP" in cipher_set:
        final_cipher = "WEP"
    elif base_type in ("OPEN", "OWE"):
        final_cipher = "None"

    return final_auth, final_cipher


def load_baseline(target_ssids):
    """
    Reads the whitelist DB and returns:
      - baseline_profiles: dict[bssid] = {profile fields}
      - known_bssids_per_ssid: dict[ssid] = set(bssids)
    """
    db_path = config["general"]["db_name"]
    baseline_profiles = {}
    known_per_ssid = defaultdict(set)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        placeholders = ",".join("?" for _ in target_ssids)
        query = (
            "SELECT ssid, bssid, channel, avg_rssi, stddev_rssi, "
            "privacy_raw, cipher_raw, authentication_raw, avg_beacon_rate "
            f"FROM whitelist WHERE ssid IN ({placeholders})"
        )
        cursor.execute(query, target_ssids)

        rows = cursor.fetchall()
        conn.close()
    except sqlite3.Error as e:
        print(f"DB Error loading baseline: {e}")
        return None, None

    if not rows:
        print(f"Warning: No baseline profiles for SSIDs: {', '.join(target_ssids)}")
        return None, None

    for ssid, bssid, chan, avg_r, std_r, priv, ciph, auth, avg_br in rows:
        b_lower = bssid.lower()

        privacy_set = {priv} if priv else set()
        cipher_set = {ciph} if ciph else set()
        auth_set = {auth} if auth else set()

        auth_type, cipher = parse_auth_details(privacy_set, cipher_set, auth_set)

        profile = {
            "ssid": ssid,
            "channel": chan,
            "avg_rssi": avg_r,
            "stddev_rssi": std_r,
            "auth_type": auth_type,
            "cipher": cipher,
            "avg_beacon_rate": avg_br,
        }

        baseline_profiles[b_lower] = profile
        known_per_ssid[ssid].add(b_lower)

    print(
        f"Loaded {len(baseline_profiles)} profiles " f"for {len(known_per_ssid)} SSIDs."
    )

    return baseline_profiles, known_per_ssid


def parse_airodump_csv(csv_path):
    """
    Reads an airodump-ng CSV and returns a pandas DataFrame of the AP section.
    """
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            in_ap = False
            header = []
            data = []

            for line in f:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("BSSID,"):
                    in_ap = True
                    header = [h.strip() for h in line.split(",")]
                    # standardize header names
                    header = [h.replace("# beacons", "#Beacons") for h in header]
                    header = [h.replace(" PWR", "Power") for h in header]
                    # rename 'channel' to 'CH'
                    header = ["CH" if h == "channel" else h for h in header]
                    continue

                if line.startswith("Station MAC,"):
                    break

                if in_ap:
                    parts = line.split(",", maxsplit=len(header) - 1)
                    if len(parts) == len(header):
                        entry = {key: val.strip() for key, val in zip(header, parts)}
                        data.append(entry)

        if not data:
            return pd.DataFrame()

        df = pd.DataFrame(data)

        # Convert numeric columns
        for col in ["Power", "#Beacons", "#Data", "CH"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        if "ESSID" in df.columns:
            df["ESSID"] = df["ESSID"].str.strip()

        return df

    except FileNotFoundError:
        print(f"Warning: CSV not found: {csv_path}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error parsing CSV {csv_path}: {e}")
        return pd.DataFrame()


# v3 new rate logic
def run_beacon_rate_profiling_scapy(iface):
    """
    After airodump-ng profiling, run Scapy to calculate "real" beacon rates.
    Update the database with Scapy-based calculated beacon rates

    Args:
        iface (string): interface to use
    """
    db_path = config["general"]["db_name"]
    profiling = config["profiling"]
    target_ssids = profiling["target_ssids"]
    sniff_time = 30
    beacon_window = 30
    print(f"Sniffing {sniff_time} seconds on interface {iface}...")
    bssid_timestamps = defaultdict(list)

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if not pkt.haslayer(Dot11):
                return
            bssid = pkt[Dot11].addr2
            ssid = monitor_logic.extract_ssid(pkt)
            if not bssid or not ssid:
                return
            if ssid not in target_ssids:
                return
            bssid = bssid.lower()
            ts = pkt.time
            bssid_timestamps[bssid].append(ts)

    scapy.sniff(iface=iface, prn=handler, store=False, timeout=sniff_time)
    print(f"Captured beacons for {len(bssid_timestamps)} APs. Updating DB...")
    # Update database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for bssid, timestamps in bssid_timestamps.items():
        if len(timestamps) < 2:
            continue

        timestamps.sort()
        first = timestamps[0]
        last = timestamps[-1]
        duration = max(last - first, 1.0)

        beacon_rate = round(len(timestamps) / duration, 2)

        print(f"  {bssid} rate: {beacon_rate}/s over {duration:.1f}s")

        cursor.execute(
            "UPDATE whitelist SET avg_beacon_rate = ? WHERE bssid = ?;",
            (beacon_rate, bssid),
        )

    conn.commit()
    conn.close()

    print("Beacon rate update complete.")


def run_profiling(iface):
    """
    Runs airodump-ng once, then parses and stores the results.
    """
    print("\n--- Profiling Phase ---")
    print(f"Interface: {iface}")

    profiling = config["profiling"]
    general = config["general"]

    target_ssids = profiling["target_ssids"]
    channels = general["channels_to_scan"]
    dwell_ms = profiling["dwell_time_ms"]
    cycles = profiling["scan_cycles"]
    temp_dir = general["temp_dir"]
    prefix = os.path.join(temp_dir, "profile_scan")

    dwell_s = dwell_ms / 1000.0
    total = max(10.0, len(channels) * dwell_s * cycles) + 2.0

    # prepare temp directory
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)

    cmd = [
        "airodump-ng",
        "--write",
        prefix,
        "-c",
        ",".join(map(str, channels)),
        "-f",
        str(dwell_ms),
        "--write-interval",
        "1",
        "--output-format",
        "csv",
        iface,
    ]

    print(f"Running: {' '.join(cmd)}")
    print(f"Expected duration: ~{total:.0f}s")

    process = None

    start = time.time()
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
        )

        end = start + total
        while time.time() < end:
            if process.poll() is not None:
                print("airodump-ng exited early.")
                break
            try:
                time.sleep(0.5)
            except KeyboardInterrupt:
                print("Interrupted by user.")
                raise

    except KeyboardInterrupt:
        print("Profiling interrupted.")
    except Exception as e:
        print(f"Error during profiling: {e}")
    finally:
        if process is not None and process.poll() is None:
            print("Terminating airodump-ng...")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(1)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                process.wait(timeout=5)
            except Exception:
                pass

    # process CSV
    csvs = glob.glob(f"{prefix}-*.csv")
    if not csvs:
        print("No CSV output found.")
        return

    main_csv = sorted(csvs)[0]
    print(f"Parsing: {main_csv}")
    df = parse_airodump_csv(main_csv)

    if df.empty:
        print("No APs parsed.")
        return

    # filter by ESSID
    df = df[df["ESSID"].isin(target_ssids)]

    if df.empty:
        print(f"No APs for SSIDs: {', '.join(target_ssids)}")
        return

    print(f"Found {len(df)} AP entries.")

    # aggregate
    agg = defaultdict(
        lambda: {
            "ssid": None,
            "rssi": [],
            "channels": defaultdict(list),
            "beacons": 0,
            "privacy": set(),
            "cipher": set(),
            "auth": set(),
        }
    )

    for _, row in df.iterrows():
        b = row["BSSID"]
        if not b or len(b) != 17:
            continue

        ssid = row["ESSID"]
        pwr = row["Power"]
        bc = row["#Beacons"]
        pr = row.get("Privacy", "").strip()
        cr = row.get("Cipher", "").strip()
        ar = row.get("Authentication", "").strip()
        ch = row["CH"]

        rec = agg[b]
        if not rec["ssid"]:
            rec["ssid"] = ssid

        if pd.notna(pwr):
            rec["rssi"].append(int(pwr))
            rec["channels"][int(ch)].append(int(pwr))

        if pd.notna(bc):
            rec["beacons"] += int(bc)

        if pr:
            rec["privacy"].add(pr)
        if cr:
            rec["cipher"].add(cr)
        if ar:
            rec["auth"].add(ar)

    # compute and save
    now = datetime.datetime.now().isoformat()
    count = 0
    # duration = max(time.time() - start, 1.0)

    for b, data in agg.items():
        if not data["ssid"]:
            continue

        if data["rssi"]:
            avg_rssi = round(statistics.mean(data["rssi"]), 2)
            std_rssi = (
                round(statistics.stdev(data["rssi"]), 2)
                if len(data["rssi"]) > 1
                else 0.0
            )
        else:
            avg_rssi = None
            std_rssi = None

        best_chan = None
        best_avg = -999
        for ch, lst in data["channels"].items():
            avg_ch = statistics.mean(lst)
            if avg_ch > best_avg:
                best_avg = avg_ch
                best_chan = ch

        # v2 rate logic
        # rate = round(data["beacons"] / duration, 2)

        priv = sorted(data["privacy"])[0] if data["privacy"] else None
        cip = sorted(data["cipher"])[0] if data["cipher"] else None
        auth = sorted(data["auth"])[0] if data["auth"] else None

        profile = {
            "ssid": data["ssid"],
            "bssid": b,
            "channel": best_chan,
            "avg_rssi": avg_rssi,
            "stddev_rssi": std_rssi,
            "privacy_raw": priv,
            "cipher_raw": cip,
            "authentication_raw": auth,
            "avg_beacon_rate": None,
            "profiled_time": now,
        }

        print(
            f"Saving {profile['ssid']} ({b}) "
            f"Ch:{best_chan} RSSI:{avg_rssi}±{std_rssi} "
            f"Priv:'{priv}' Ciph:'{cip}' Auth:'{auth}'"
        )
        add_to_whitelist(profile)
        count += 1

    print("Now sniffing for normal beacon rate...")
    run_beacon_rate_profiling_scapy(iface=iface)

    print(f"{count} profiles saved.")

    try:
        shutil.rmtree(config["general"]["temp_dir"])
        print("Temp dir removed.")
    except Exception:
        print("Warning: could not remove temp dir.")


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AP Profiling & Monitoring Tool")
    parser.add_argument(
        "-c", "--config", default="config.json", help="Config file path"
    )
    parser.add_argument("-f", "--profile", action="store_true", help="Run profiling")
    parser.add_argument("-m", "--monitor", action="store_true", help="Run monitoring")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.profile and args.monitor:
        print("Error: --profile and --monitor are mutually exclusive.")
        sys.exit(1)

    if not (args.profile or args.monitor):
        print("Error: must specify --profile or --monitor.")
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print("Error: root privileges required.")
        sys.exit(1)

    init_db()

    iface = config["general"]["interface"]
    monitor_iface = None
    failed = False

    try:
        monitor_iface = set_monitor_mode(iface, enable=True)
        if not monitor_iface:
            raise RuntimeError("Failed to enable monitor mode.")

        if args.profile:
            run_profiling(monitor_iface)

        if args.monitor:
            ssids = config["monitoring"]["target_ssids"]
            profiles, known = load_baseline(ssids)
            if profiles is None:
                raise RuntimeError("No baseline profiles.")

            monitor_logic.run_monitoring(
                iface=monitor_iface, config=config, profiles=profiles, known=known
            )

    except Exception as e:
        print(f"Fatal error: {e}")
        failed = True

    finally:
        if monitor_iface:
            set_monitor_mode(monitor_iface, enable=False)
        elif not failed:
            print("Skipping monitor-mode disable (none active).")

    print("Exiting.")
