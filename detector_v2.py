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
import scapy.all as scapy

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
                    header = [h.replace(' # ', '#') for h in header]
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
        'beacons_total': 0, 'privacy_strings': set()
    })

    print(target_ap_df) # Debug

    for index, row in target_ap_df.iterrows():
        bssid = row.get('BSSID');
        if not bssid or not isinstance(bssid, str) or len(bssid) != 17 : continue
        ssid = row.get('ESSID', '').strip(); power = row.get('Power')
        beacons = row.get('#Beacons', 0) # Use standardized name
        privacy_raw = row.get('Privacy', '').strip()
        cipher_raw = row.get('Cipher', '').strip()
        authentication_raw = row.get('Authentication', '').strip()
        channel = row.get('CH') # Use standardized name

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
    # *** UPDATED ARGUMENT PARSING ***
    parser = argparse.ArgumentParser(description="AP Profiling Tool using a single airodump-ng scan")
    parser.add_argument("-c", "--config", default="config.json",
                        help="Path to the configuration file (default: config.json)")
    parser.add_argument("-f", "--profile", action="store_true",
                        help="Run the AP profiling process.") # Changed 'f' to '--profile', added action

    args = parser.parse_args()
    config = load_config(args.config) # Load config globally

    # *** EXECUTION CONDITIONED ON THE FLAG ***
    if args.profile:
        if os.geteuid() != 0: print("Error: Root privileges required."); sys.exit(1)

        init_db()
        monitor_iface_active = None
        original_iface = config['general']['interface']

        try:
            print("Profile flag detected, starting profiling process...")
            monitor_iface_active = set_monitor_mode(original_iface, enable=True)
            if not monitor_iface_active: raise RuntimeError(f"Failed to enable monitor mode on {original_iface}.")

            run_profiling(monitor_iface_active) # Call the main profiling function

        except Exception as e:
            print(f"\nAn error occurred during profiling: {e}")
            import traceback; traceback.print_exc()
        finally:
            # Cleanup logic
            iface_to_stop = monitor_iface_active
            print(f"\nCleaning up: Disabling monitor mode on {iface_to_stop}...")
            try:
                set_monitor_mode(iface_to_stop, enable=False)
            except Exception as cleanup_err: print(f"Error during monitor mode cleanup: {cleanup_err}")

            temp_dir = config['general']['temp_dir']
            if os.path.exists(temp_dir):
                try: shutil.rmtree(temp_dir)
                except Exception: pass # Ignore cleanup error here
            print("Exiting Profiling Tool.")

    else:
        # If -f/--profile flag was not provided
        print("Usage: sudo python3 your_script_name.py --profile [-c config.json]")
        parser.print_help()
        sys.exit(0)