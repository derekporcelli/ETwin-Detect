#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import json
import time
import pandas as pd
import glob
import signal
import statistics
import datetime
import sqlite3
import re
import shutil # For removing temp directory
from collections import defaultdict
import monitor_logic

# --- Configuration Loading ---
CONFIG_DEFAULTS = {
    "general": {
        "interface": "wlan0",
        "db_name": "ap_profiles_airodump.db",
        "channels_to_scan": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], # Example: 2.4GHz channels
        "temp_dir": "/tmp/airodump_profiling"
    },
    "profiling": {
        "dwell_time_ms": 5000, # Stay 5 seconds on each channel
        "scan_cycles": 1,      # Perform 1 full cycle through channels
        "target_ssids": ['malmalmal']     # Must be specified in config file - used for filtering AFTER scan
    },
    "monitoring": { 
        "target_ssids": ['malmalmal'], 
        "scan_dwell_seconds": 2, 
        "rssi_threshold_stdev": 3.0, 
        "rssi_threshold_dbm_abs": 20, 
        "rssi_spread_stdev_threshold": 10.0, 
        "rssi_spread_range_threshold": 25.0, 
        "beacon_rate_threshold_percent": 50.0, 
        "alert_cooldown_seconds": 60 
        }
}

def load_config(filepath):
    """Loads configuration from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            config_from_file = json.load(f)

        # Deep merge might be better if config structure gets complex, but simple update works here
        merged_config = CONFIG_DEFAULTS.copy()
        for key, value in config_from_file.items():
            if key in merged_config and isinstance(merged_config[key], dict) and isinstance(value, dict):
                 merged_config[key].update(value)
            else:
                merged_config[key] = value

        print(f"Configuration loaded from '{filepath}'")
        # Validation
        if not merged_config['profiling']['target_ssids']:
             print("Error: 'profiling.target_ssids' cannot be empty in the config.")
             sys.exit(1)
        if not merged_config['general']['channels_to_scan']:
             print("Error: 'general.channels_to_scan' cannot be empty in the config.")
             sys.exit(1)
        if merged_config['profiling']['dwell_time_ms'] <= 0:
             print("Error: 'profiling.dwell_time_ms' must be positive.")
             sys.exit(1)
        if merged_config['profiling']['scan_cycles'] <= 0:
             print("Error: 'profiling.scan_cycles' must be positive.")
             sys.exit(1)
        return merged_config
    except FileNotFoundError: print(f"Error: Config file '{filepath}' not found."); sys.exit(1)
    except json.JSONDecodeError as e: print(f"Error: Could not parse config '{filepath}': {e}"); sys.exit(1)
    except Exception as e: print(f"Error loading config: {e}"); sys.exit(1)

# --- Global variable to hold config ---
config = None

# --- Network Interface Management ---
# (Using the robust set_monitor_mode from previous iteration)
def set_monitor_mode(iface, enable=True):
    """Enables or disables monitor mode using airmon-ng."""
    try:
        subprocess.run(['which', 'airmon-ng'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
         print("Error: 'airmon-ng' command not found. Install aircrack-ng suite.")
         return None

    action = "start" if enable else "stop"
    print(f"{'Enabling' if enable else 'Disabling'} monitor mode on {iface}...")

    try:
        if enable:
            print("Checking for and killing interfering processes...")
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True, timeout=15)
            print("Interfering processes check/kill executed.")

            proc = subprocess.run(['airmon-ng', action, iface], check=True, capture_output=True, text=True, timeout=15)

            monitor_iface_active = f"{iface}mon"
            return monitor_iface_active

        else: # Disabling
            print(f"Monitor mode stop command executed for {iface}.")
            subprocess.run(['airmon-ng', 'stop', iface], check=False, capture_output=True, timeout=15)
            print("Attempting to restart NetworkManager...")
            subprocess.run(['systemctl', 'start', 'NetworkManager'], check=False, capture_output=True, timeout=15)
            return iface

    except subprocess.CalledProcessError as e: print(f"Error airmon-ng: {e.stderr}"); return None
    except subprocess.TimeoutExpired as e: print(f"Error: airmon-ng command timed out."); return None
    except Exception as e: print(f"Unexpected error in set_monitor_mode: {e}"); return None


# --- Database Operations ---
def init_db():
    """Initializes the SQLite database and creates the whitelist table with raw auth fields."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # *** UPDATED SCHEMA ***
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL PRIMARY KEY,
            channel INTEGER,
            avg_rssi REAL,
            stddev_rssi REAL,
            privacy_raw TEXT,         -- Storing raw values now
            cipher_raw TEXT,          -- Storing raw values now
            authentication_raw TEXT,  -- Storing raw values now
            avg_beacon_rate REAL,
            profiled_time TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()
    print(f"Database '{db_path}' initialized.")

def add_to_whitelist(profile_data):
    """Adds or updates an AP profile (with raw auth fields) in the whitelist."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # *** UPDATED SQL AND PARAMETERS ***
    cursor.execute('''
        INSERT OR REPLACE INTO whitelist
        (ssid, bssid, channel, avg_rssi, stddev_rssi, privacy_raw, cipher_raw, authentication_raw, avg_beacon_rate, profiled_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        profile_data['ssid'], profile_data['bssid'].lower(), profile_data['channel'],
        profile_data['avg_rssi'], profile_data['stddev_rssi'],
        profile_data['privacy_raw'],  
        profile_data['cipher_raw'],       
        profile_data['authentication_raw'],
        profile_data['avg_beacon_rate'], profile_data['profiled_time']
    ))
    conn.commit()
    conn.close()

def parse_auth_details(privacy_set, cipher_set, auth_set):
    """Determines standardized Auth Type and Cipher from separate field sets."""
    final_auth_type = "Unknown"; final_cipher = "Unknown"; base_type = "Unknown"
    if "OWE" in auth_set: base_type = "OWE"
    elif "WPA3" in privacy_set: base_type = "WPA3"
    elif "WPA2" in privacy_set: base_type = "WPA2"
    elif "WPA" in privacy_set and not ("WPA2" in privacy_set or "WPA3" in privacy_set): base_type = "WPA"
    elif "WEP" in privacy_set and not ("WPA" in privacy_set or "WPA2" in privacy_set or "WPA3" in privacy_set or base_type == "OWE"): base_type = "WEP"
    elif "OPN" in privacy_set and base_type == "Unknown": base_type = "OPEN"
    final_auth_type = base_type
    if base_type == "WPA3":
        if "SAE" in auth_set: final_auth_type += "-SAE"
        elif "MGT" in auth_set: final_auth_type += "-EAP"
    elif base_type in ["WPA2", "WPA"]:
        if "PSK" in auth_set: final_auth_type += "-PSK"
        elif "MGT" in auth_set: final_auth_type += "-EAP"
    if "GCMP-256" in cipher_set: final_cipher = "GCMP-256"
    elif "GCMP-128" in cipher_set: final_cipher = "GCMP-128"
    elif "GCMP" in cipher_set and final_cipher == "Unknown": final_cipher = "GCMP-256"
    elif "CCMP" in cipher_set: final_cipher = "CCMP"
    elif "TKIP" in cipher_set: final_cipher = "TKIP"
    elif ("WEP" in cipher_set or "WEP40" in cipher_set or "WEP104" in cipher_set) and base_type == "WEP": final_cipher = "WEP"
    elif base_type in ["OPEN", "OWE"]: final_cipher = "None"
    if "CCMP" in cipher_set and "TKIP" in cipher_set: final_cipher = "CCMP" # Prioritize CCMP
    if final_cipher == "Unknown":
        if final_auth_type.startswith("WPA3"): final_cipher = "GCMP-256"
        elif final_auth_type.startswith("WPA2"): final_cipher = "CCMP"
        elif final_auth_type in ["WPA", "WPA-PSK", "WPA-EAP"]: final_cipher = "TKIP"
        elif final_auth_type == "WEP": final_cipher = "WEP"
    return final_auth_type, final_cipher

def load_baseline(target_ssids):
    """Loads baseline profiles and parses raw auth strings."""
    db_path = config['general']['db_name']; baseline_profiles = {}; known_bssids_per_ssid = defaultdict(set)
    try:
        conn = sqlite3.connect(db_path); cursor = conn.cursor()
        placeholders = ','.join('?' * len(target_ssids))
        query = f"""SELECT ssid, bssid, channel, avg_rssi, stddev_rssi, privacy_raw, cipher_raw, authentication_raw, avg_beacon_rate FROM whitelist WHERE ssid IN ({placeholders}) """
        cursor.execute(query, target_ssids); rows = cursor.fetchall(); conn.close()
        if not rows: print(f"Warning: No baseline profiles found for SSIDs: {', '.join(target_ssids)}"); return None, None
        for row in rows:
            ssid, bssid, chan, avg_r, std_r, priv_r, ciph_r, auth_r, avg_br = row; bssid_lower = bssid.lower()
            privacy_set = {priv_r} if priv_r else set(); cipher_set = {ciph_r} if ciph_r else set(); auth_set = {auth_r} if auth_r else set()
            parsed_auth_type, parsed_cipher = parse_auth_details(privacy_set, cipher_set, auth_set) # Use helper
            profile = { 'ssid': ssid, 'channel': chan, 'avg_rssi': avg_r, 'stddev_rssi': std_r, 'auth_type': parsed_auth_type, 'cipher': parsed_cipher, 'avg_beacon_rate': avg_br }
            baseline_profiles[bssid_lower] = profile; known_bssids_per_ssid[ssid].add(bssid_lower)
        print(f"Loaded and parsed {len(baseline_profiles)} baseline profiles for {len(known_bssids_per_ssid)} SSIDs.")
        return baseline_profiles, known_bssids_per_ssid
    except sqlite3.Error as e: print(f"DB Error loading baseline: {e}"); return None, None
    except Exception as e: print(f"Error loading baseline: {e}"); return None, None

# --- Helper Functions ---
def parse_airodump_csv(csv_path):
    """Parses the airodump-ng CSV file to extract the AP list into a DataFrame."""
    aps_data = []
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            in_ap_section = False; header = []
            for line in f:
                line = line.strip();
                if not line: continue
                if line.startswith("BSSID,"):
                    in_ap_section = True; header = [h.strip() for h in line.split(',')]
                    # Standardize headers that might vary
                    header = [h.replace('# beacons', '#Beacons') for h in header]
                    header = [h.replace(' PWR', 'Power') for h in header]
                    header = [h if h != 'channel' else 'CH' for h in header] # Standardize channel
                    continue
                if line.startswith("Station MAC,"): break
                if in_ap_section:
                    values = [v.strip() for v in line.split(',', maxsplit=len(header) - 1)];
                    if len(values) == len(header): aps_data.append(dict(zip(header, values)))
        if not aps_data: return pd.DataFrame()
        df = pd.DataFrame(aps_data)
        # Convert columns using standardized names
        for col in ['Power', '#Beacons', '#Data', 'CH']:
            if col in df.columns: df[col] = pd.to_numeric(df[col], errors='coerce')
        if 'ESSID' in df.columns: df['ESSID'] = df['ESSID'].str.strip()
        return df
    except FileNotFoundError: print(f"Warning: CSV file not found: {csv_path}"); return pd.DataFrame()
    except Exception as e: print(f"Error parsing CSV {csv_path}: {e}"); return pd.DataFrame()

# --- Main Profiling Function (Single Scan) ---
def run_profiling(iface):
    """Runs the profiling phase using a single airodump-ng scan."""
    print(f"\n--- Starting Profiling Phase (Single Scan) ---")
    print(f"Interface: {iface}")

    target_ssids = config['profiling']['target_ssids']
    channels_to_scan = config['general']['channels_to_scan']
    dwell_time_ms = config['profiling']['dwell_time_ms']
    scan_cycles = config['profiling']['scan_cycles']
    temp_dir = config['general']['temp_dir']
    scan_prefix = os.path.join(temp_dir, "profile_scan") # Generic prefix

    # Calculate total duration
    dwell_seconds = dwell_time_ms / 1000.0
    num_channels = len(channels_to_scan)
    # Ensure at least minimum time even if cycles/dwell is low, add small buffer
    min_duration = 10.0 # seconds
    calculated_duration = num_channels * dwell_seconds * scan_cycles
    total_duration = max(min_duration, calculated_duration) + 2.0 # Add 2s buffer
    print(f"Scanning channels: {', '.join(map(str, channels_to_scan))}")
    print(f"Dwell time per channel: {dwell_seconds:.1f}s")
    print(f"Scan cycles: {scan_cycles}")
    print(f"Calculated total scan duration: ~{total_duration:.0f} seconds")

    # Create or clear temporary directory
    if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    print(f"Using temporary directory: {temp_dir}")

    process = None # Initialize process variable
    start_time = time.time()
    try:
        # Construct channel list string
        channel_string = ",".join(map(str, channels_to_scan))

        # Construct airodump-ng command (NO --essid filter)
        cmd = [
            'airodump-ng',
            '--write', scan_prefix,
            '-c', channel_string,
            '-f', str(dwell_time_ms), # Dwell time in ms
            '--write-interval', '1', # Update CSV every second
            '--output-format', 'csv',
            iface
        ]
        print(f"Running command: {' '.join(cmd)}")
        print(f"Scan will run for approximately {total_duration:.0f} seconds...")

        # Start airodump-ng
        # Use os.setsid to create a new process group for reliable termination
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

        # Wait for the specified duration, checking for early exit or interrupt
        end_time = start_time + total_duration
        while time.time() < end_time:
            if process.poll() is not None: # Check if process exited early
                 print("\nWarning: airodump-ng process exited prematurely.")
                 break
            try:
                 time.sleep(0.5) # Sleep briefly
            except KeyboardInterrupt:
                 print("\nInterrupt received, stopping scan...")
                 raise # Re-raise to be caught by outer try/except

        actual_duration = time.time() - start_time
        print(f"\nScan duration finished ({actual_duration:.1f}s). Stopping airodump-ng...")

    except KeyboardInterrupt:
        print("\nProfiling interrupted by user.")
        # Cleanup happens in finally block
    except Exception as e:
        print(f"\nAn error occurred during airodump execution: {e}")
        # Cleanup happens in finally block
    finally:
        # Ensure airodump-ng process is terminated
        if process and process.poll() is None: # Check if process exists and is running
             print("Terminating airodump-ng process...")
             try:
                 # Send SIGTERM to the entire process group first
                 os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                 time.sleep(1) # Give it a second
                 if process.poll() is None: # If still alive, send SIGKILL
                      print("Process did not exit via SIGTERM, sending SIGKILL.")
                      os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                 process.wait(timeout=5) # Wait for process to avoid zombies
                 print("Airodump process terminated.")
             except ProcessLookupError:
                 print("Process already finished.")
             except Exception as term_err:
                 print(f"Error during process termination: {term_err}")

    # --- Process Aggregated Data ---
    print("\n--- Processing Collected Data ---")

    # Find the main CSV file (usually ends in -01.csv)
    csv_files = glob.glob(f"{scan_prefix}-*.csv")
    if not csv_files:
        print("Error: No airodump-ng CSV file found.")
        return # Cannot proceed

    # Assume the main file is the first one found (usually -01.csv)
    main_csv_file = sorted(csv_files)[0]
    print(f"Parsing CSV file: {main_csv_file}")

    all_ap_df = parse_airodump_csv(main_csv_file)

    if all_ap_df.empty:
        print("No AP data parsed from CSV file.")
        return

    # --- Filter for Target SSIDs ---
    target_ssids_set = set(target_ssids)
    # Handle potential NaN values in ESSID column before filtering
    target_ap_df = all_ap_df[
        all_ap_df['ESSID'].notna() & all_ap_df['ESSID'].isin(target_ssids_set)
    ].copy() # Use .copy() to avoid SettingWithCopyWarning

    if target_ap_df.empty:
        print(f"No APs found matching target SSIDs: {', '.join(target_ssids)}")
        return

    print(f"Found {len(target_ap_df)} entries matching target SSIDs.")

    # --- Aggregate data per BSSID from the filtered DataFrame ---
    aggregated_results = defaultdict(lambda: {
        'ssid': None, 'rssi_values': [], 'channel_rssi': defaultdict(list),
        'beacons_total': 0,
        'privacy_raw_values': set(), # Collect unique raw strings
        'cipher_raw_values': set(),
        'authentication_raw_values': set()
    })

    # print(target_ap_df) # Debug

    for index, row in target_ap_df.iterrows():
        bssid = row.get('BSSID');
        if not bssid or not isinstance(bssid, str) or len(bssid) != 17 : continue
        ssid = row.get('ESSID', '').strip(); power = row.get('Power')
        beacons = row.get('#Beacons', 0) # Use standardized name
        privacy_raw = row.get('Privacy', '').strip()
        cipher_raw = row.get('Cipher', '').strip()
        authentication_raw = row.get('Authentication', '').strip()
        channel = row.get('CH') # Use standardized name

        # print(f"Debug: beacons: {beacons}")

        if not aggregated_results[bssid]['ssid'] and ssid: aggregated_results[bssid]['ssid'] = ssid
        if pd.notna(power) and -99 <= power < 0:
            aggregated_results[bssid]['rssi_values'].append(int(power))
            if pd.notna(channel): aggregated_results[bssid]['channel_rssi'][int(channel)].append(int(power))
        if pd.notna(beacons): aggregated_results[bssid]['beacons_total'] += int(beacons)
        if privacy_raw: aggregated_results[bssid]['privacy_raw_values'].add(privacy_raw)
        if cipher_raw: aggregated_results[bssid]['cipher_raw_values'].add(cipher_raw)
        if authentication_raw: aggregated_results[bssid]['authentication_raw_values'].add(authentication_raw)

    # --- Calculate Features and Save to DB ---
    print("Calculating final profiles and saving to database...")
    profile_time = datetime.datetime.now().isoformat(); saved_count = 0
    actual_scan_duration_seconds = actual_duration if 'actual_duration' in locals() and actual_duration > 1 else total_duration

    for bssid, data in aggregated_results.items():
        if not data['ssid']: continue
        avg_rssi = round(statistics.mean(data['rssi_values']), 2) if data['rssi_values'] else None
        stddev_rssi = round(statistics.stdev(data['rssi_values']), 2) if len(data['rssi_values']) >= 2 else 0.0
        primary_channel = None; best_avg_rssi_for_chan = -100.0
        if data['channel_rssi']:
            for chan, rssi_list in data['channel_rssi'].items():
                if rssi_list: chan_avg = statistics.mean(rssi_list);
                if chan_avg > best_avg_rssi_for_chan: best_avg_rssi_for_chan = chan_avg; primary_channel = chan
            if primary_channel is None and data['channel_rssi']: primary_channel = list(data['channel_rssi'].keys())[0]
        avg_beacon_rate = round(data['beacons_total'] / actual_scan_duration_seconds, 2) if actual_scan_duration_seconds > 0 else 0.0

        # *** SELECT REPRESENTATIVE RAW STRINGS ***
        # Take the first one alphabetically, or None if empty set
        privacy_repr = sorted(list(data['privacy_raw_values']))[0] if data['privacy_raw_values'] else None
        cipher_repr = sorted(list(data['cipher_raw_values']))[0] if data['cipher_raw_values'] else None
        auth_repr = sorted(list(data['authentication_raw_values']))[0] if data['authentication_raw_values'] else None

        # *** PREPARE DB DATA WITH RAW FIELDS ***
        profile_data = {
            'ssid': data['ssid'], 'bssid': bssid, 'channel': primary_channel,
            'avg_rssi': avg_rssi, 'stddev_rssi': stddev_rssi,
            'privacy_raw': privacy_repr,
            'cipher_raw': cipher_repr,
            'authentication_raw': auth_repr,
            'avg_beacon_rate': avg_beacon_rate, 'profiled_time': profile_time
        }

        print(f"  -> Saving: {profile_data['ssid']} ({profile_data['bssid']}) Ch:{profile_data['channel']} RSSI:{profile_data['avg_rssi']} +/- {profile_data['stddev_rssi']} "
              f"Privacy:'{profile_data['privacy_raw']}' Cipher:'{profile_data['cipher_raw']}' Auth:'{profile_data['authentication_raw']}' Rate:{profile_data['avg_beacon_rate']:.2f}/s")
        add_to_whitelist(profile_data) # Call the updated add function
        saved_count += 1

    print(f"\nWhitelist update complete. Profiles saved: {saved_count}")
    try: print(f"Removing temporary directory: {temp_dir}"); shutil.rmtree(temp_dir)
    except Exception as e: print(f"Warning: Failed to remove {temp_dir}: {e}")

# --- Main Execution Block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AP Profiling (airodump) and Monitoring (Scapy) Tool"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Path to config file"
    )
    parser.add_argument(
        "-f", "--profile",
        action="store_true",
        help="Run AP profiling (airodump-ng)."
    )
    parser.add_argument(
        "-m", "--monitor",
        action="store_true",
        help="Run AP monitoring (Scapy)."
    )
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Validate mutually exclusive modes
    if args.profile and args.monitor:
        print("Error: Cannot run --profile and --monitor simultaneously.")
        sys.exit(1)

    if not args.profile and not args.monitor:
        print("Error: Use --profile or --monitor.")
        parser.print_help()
        sys.exit(1)

    # Ensure we have root
    if os.geteuid() != 0:
        print("Error: Root privileges required.")
        sys.exit(1)

    # Initialize database
    init_db()

    # Prepare interface variables
    monitor_iface_active = None
    original_iface = config["general"]["interface"]
    mode_failed = False

    try:
        # Enable monitor mode
        print(f"Attempting to enable monitor mode on {original_iface}...")
        monitor_iface_active = set_monitor_mode(
            iface=original_iface,
            enable=True
        )

        if not monitor_iface_active:
            raise RuntimeError(
                f"Failed to enable monitor mode on {original_iface}."
            )

        print(f"Monitor mode appears active on {monitor_iface_active}")

        # Profiling or Monitoring
        if args.profile:
            print("Starting profiling process (airodump-ng)...")
            run_profiling(monitor_iface_active)

        elif args.monitor:
            print("Starting monitoring process (Scapy)...")
            target_ssids_mon = config["monitoring"]["target_ssids"]
            baseline_profiles, known_bssids = load_baseline(target_ssids_mon)

            if baseline_profiles is None:
                print("Cannot start monitoring without baseline profiles.")
                raise ValueError("Baseline loading failed")

            monitor_logic.run_monitoring(
                iface=monitor_iface_active,
                config=config,
                baseline_profiles=baseline_profiles,
                known_bssids=known_bssids
            )

    except Exception as e:
        print(f"\nAn error occurred in main execution: {e}")
        import traceback
        traceback.print_exc()
        mode_failed = True

    finally:
        # Determine which interface to disable
        if monitor_iface_active:
            iface_to_stop = monitor_iface_active
        else:
            iface_to_stop = original_iface

        # Disable monitor mode if it was enabled
        if monitor_iface_active:
            print(f"\nCleaning up: Disabling monitor mode on {iface_to_stop}...")
            try:
                set_monitor_mode(iface=iface_to_stop, enable=False)
            except Exception as cleanup_err:
                print(f"Error during monitor mode cleanup: {cleanup_err}")

        elif not mode_failed and (args.profile or args.monitor):
            print(
                "\nMonitor mode interface name unknown or setup failed, "
                "skipping automatic disable."
            )

        # Clean up profiling temp directory
        if args.profile:
            temp_dir_prof = config["general"]["temp_dir"]
            if os.path.exists(temp_dir_prof):
                try:
                    shutil.rmtree(temp_dir_prof)
                except Exception:
                    pass

        print("Exiting Tool.")
