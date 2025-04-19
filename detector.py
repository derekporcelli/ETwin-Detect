#!/usr/bin/env python3

import scapy.all as scapy
import sqlite3
import subprocess
import time
import argparse
import os
import sys
from collections import defaultdict
import datetime
import json # Added for config file handling

# --- Configuration Loading ---
# Defaults (will be overridden by config file if keys exist)
CONFIG_DEFAULTS = {
    "general": {
        "interface": "wlan0",
        "db_name": "ap_profile.db",
        "channel_hop_delay_seconds": 0.5,
        "channels_to_scan": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    },
    "profiling": {
        "duration_seconds": 60,
        "target_ssids": []
    },
    "monitoring": {
        "target_ssids": [],
        "enable_deauth_prompt": False,
        "blacklist_check_interval_seconds": 30
    },
    "anomaly_thresholds": {
        "signal_strength_dbm_diff": 15,
        "beacon_interval_ms_diff": 10
    }
}

def load_config(filepath):
    """Loads configuration from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            config_from_file = json.load(f)

        # Merge loaded config with defaults (deep merge is better for nested dicts)
        # Simple update for top-level keys, then nested
        merged_config = CONFIG_DEFAULTS.copy()
        for key, value in config_from_file.items():
            if key in merged_config and isinstance(merged_config[key], dict):
                 merged_config[key].update(value) # Update nested dicts
            else:
                 merged_config[key] = value # Replace top-level values/add new keys

        print(f"Configuration loaded from '{filepath}'")
        return merged_config
    except FileNotFoundError:
        print(f"Error: Configuration file '{filepath}' not found.")
        print("Please create a config file (e.g., config.json) or specify the correct path.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Could not parse configuration file '{filepath}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred loading config: {e}")
        sys.exit(1)

# --- Global variable to hold config ---
config = None

# --- Database Operations ---
# (Use config['general']['db_name'] instead of DB_NAME constant)

def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Whitelist table... (same as before)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL PRIMARY KEY,
            channel INTEGER,
            avg_signal INTEGER,
            auth_schemes TEXT,
            beacon_interval INTEGER,
            profiled_time TEXT
        )
    ''')
    # Blacklist table... (same as before)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            bssid TEXT NOT NULL PRIMARY KEY,
            ssid TEXT,
            channel INTEGER,
            reason TEXT,
            first_detected TEXT,
            last_detected TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print(f"Database '{db_path}' initialized.")

def add_to_whitelist(profile_data):
    """Adds or updates an AP profile in the whitelist."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO whitelist
        (ssid, bssid, channel, avg_signal, auth_schemes, beacon_interval, profiled_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        profile_data['ssid'],
        profile_data['bssid'],
        profile_data['channel'],
        profile_data['avg_signal'],
        profile_data['auth_schemes'],
        profile_data['beacon_interval'],
        datetime.datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()

def get_whitelist_bssid(ssid):
    """Gets all whitelisted BSSIDs for a given SSID."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT bssid FROM whitelist WHERE ssid=?", (ssid,))
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return set(results)

def get_baseline(bssid):
    """Retrieves the baseline profile for a given BSSID."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT ssid, channel, avg_signal, auth_schemes, beacon_interval FROM whitelist WHERE bssid=?", (bssid,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'ssid': row[0],
            'channel': row[1],
            'avg_signal': row[2],
            'auth_schemes': row[3],
            'beacon_interval': row[4]
        }
    return None

def add_to_blacklist(bssid, ssid, channel, reason):
    """Adds or updates an entry in the blacklist."""
    db_path = config['general']['db_name']
    now = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO blacklist (bssid, ssid, channel, reason, first_detected, last_detected)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(bssid) DO UPDATE SET
            ssid=excluded.ssid,
            channel=excluded.channel,
            reason=excluded.reason,
            last_detected=excluded.last_detected
    ''', (bssid, ssid, channel, reason, now, now))
    conn.commit()
    conn.close()
    print(f"🚨 Blacklisted: BSSID={bssid}, SSID={ssid}, Channel={channel}, Reason={reason}")

def get_blacklist():
    """Retrieves all entries from the blacklist."""
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT bssid, ssid, channel, reason, first_detected, last_detected FROM blacklist")
    results = cursor.fetchall()
    conn.close()
    return results

# --- Network Interface Management ---
# (set_monitor_mode, set_channel - functions remain the same)
# ... (copy from previous version) ...
def set_monitor_mode(iface, enable=True):
    """Enables or disables monitor mode using airmon-ng (adjust for other tools/OS)."""
    action = "start" if enable else "stop"
    print(f"{'Enabling' if enable else 'Disabling'} monitor mode on {iface}...")
    try:
        # Stop Network Manager interference
        if enable:
             subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True)
        # Start/Stop monitor mode
        proc = subprocess.run(['airmon-ng', action, iface], check=True, capture_output=True, text=True)
        # print(proc.stdout) # Less verbose output
        # Find the monitor interface name (often adds 'mon')
        monitor_iface = iface + 'mon' if enable else iface # Simplified assumption
        newly_created_mon_iface = None
        if enable:
             lines = proc.stdout.splitlines()
             for line in lines:
                 if "monitor mode enabled on" in line or "monitor mode vif enabled for" in line :
                    parts = line.split()
                    # Handle different phrasings like "... enabled on mon0)" or "... vif enabled for [phyX]wlanX on monX"
                    try:
                        on_index = parts.index("on")
                        if on_index + 1 < len(parts):
                            potential_iface = parts[on_index + 1].strip(') ')
                            # Basic check if it looks like an interface name
                            if potential_iface and not potential_iface.startswith('['):
                                newly_created_mon_iface = potential_iface
                                break
                    except ValueError: # "on" not found, maybe different wording
                         pass # Add more parsing if needed for other airmon-ng versions

             if newly_created_mon_iface and os.path.exists(f"/sys/class/net/{newly_created_mon_iface}"):
                 monitor_iface = newly_created_mon_iface
                 print(f"Monitor mode interface appears to be: {monitor_iface}")
             elif not os.path.exists(f"/sys/class/net/{monitor_iface}"):
                  print(f"Warning: Could not confirm monitor interface name. Assuming '{monitor_iface}', but it might be wrong.")
                  # Fallback or further checks might be needed


        # Bring the interface up (optional but sometimes needed)
        # if enable:
        #     subprocess.run(['ip', 'link', 'set', monitor_iface, 'up'], check=True)
        # else:
        #      # Optionally restart network manager
        #      subprocess.run(['systemctl', 'start', 'NetworkManager'], check=False)
        print(f"Monitor mode command {'executed' if enable else 'executed'} successfully.") # Adjusted message as direct confirmation is tricky
        return monitor_iface if enable else iface
    except subprocess.CalledProcessError as e:
        print(f"Error setting monitor mode: {e}")
        print(f"Stderr: {e.stderr.decode()}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'airmon-ng' (or 'ip') command not found. Is aircrack-ng suite installed and in PATH?")
        sys.exit(1)

def set_channel(iface, channel):
    """Sets the channel for the specified interface."""
    try:
        # print(f"Setting {iface} to channel {channel}...")
        subprocess.run(['iwconfig', iface, 'channel', str(channel)], check=True, capture_output=True)
        # time.sleep(0.1) # Small delay to allow channel change
    except subprocess.CalledProcessError as e:
        print(f"Error setting channel {channel} on {iface}: {e}")
        # Don't print stderr noise unless debugging: print(f"Stderr: {e.stderr.decode()}")
        pass # Continue even if setting channel fails sometimes
    except FileNotFoundError:
         print("Error: 'iwconfig' command not found. Is wireless-tools installed?")


# --- Packet Processing ---
# (get_packet_features, packet_handler_profiling, packet_handler_monitoring - functions remain mostly the same)
# ... (copy from previous version, BUT update threshold usage inside packet_handler_monitoring) ...

# Global dictionary to store profiling data before averaging
profiling_data_store = defaultdict(lambda: {'signals': [], 'channels': set(), 'auths': set(), 'beacons': [], 'ssid': None})

# State for Agarwal et al. Association Response monitoring
assoc_state = defaultdict(lambda: {'req_ts': 0, 'resp_info': []}) # Key: client_mac
ASSOC_WINDOW = 2 # Seconds to consider responses related (Could be made configurable)

def get_packet_features(pkt):
    """Extracts relevant features from Beacon or Probe Response packets."""
    features = {'bssid': None, 'ssid': None, 'channel': None, 'signal': None, 'auth_schemes': set(), 'beacon_interval': None}
    if pkt.haslayer(scapy.Dot11):
        # Use addr2 for BSSID in most management frames like Beacon, ProbeResp, AssocResp, Auth, Deauth, Disassoc
        # addr1 is DA, addr3 can be SA/DA depending on context.
        if hasattr(pkt[scapy.Dot11], 'addr2'):
            features['bssid'] = pkt[scapy.Dot11].addr2 # AP MAC address (BSSID)

        # Try getting SSID and Channel first from tagged parameters
        if pkt.haslayer(scapy.Dot11Elt):
            elt = pkt.getlayer(scapy.Dot11Elt)
            ssid_found = False
            channel_found = False
            while elt:
                try:
                    if not ssid_found and elt.ID == 0: # SSID
                        features['ssid'] = elt.info.decode('utf-8', errors='ignore')
                        ssid_found = True
                    elif not channel_found and elt.ID == 3: # DSset (Channel)
                        features['channel'] = int(elt.channel)
                        channel_found = True
                    elif elt.ID == 48: # RSN (WPA2/WPA3)
                        features['auth_schemes'].add('RSN')
                    elif elt.ID == 221 and hasattr(elt, 'info') and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'): # WPA Vendor Specific
                         features['auth_schemes'].add('WPA')

                except Exception:
                    pass # Ignore decoding/parsing errors for specific elements

                # Navigate payload safely
                if isinstance(elt.payload, scapy.Packet):
                     elt = elt.payload.getlayer(scapy.Dot11Elt)
                else:
                     break # End of elements

        # Extract Signal Strength (from RadioTap) - Best effort
        try:
             if pkt.haslayer(scapy.RadioTap):
                 # Search for dBm_AntSignal, fallback to older names if needed
                 if hasattr(pkt[scapy.RadioTap], 'dBm_AntSignal'):
                      features['signal'] = pkt[scapy.RadioTap].dBm_AntSignal
                 elif hasattr(pkt[scapy.RadioTap], 'dbm_antsignal'): # Some drivers/versions use lowercase
                      features['signal'] = pkt[scapy.RadioTap].dbm_antsignal

                 # Extract Channel from RadioTap if not found in Dot11Elt (more reliable source often)
                 if features['channel'] is None and hasattr(pkt[scapy.RadioTap], 'ChannelFrequency'):
                      freq = pkt[scapy.RadioTap].ChannelFrequency
                      if 2412 <= freq <= 2484: # 2.4 GHz
                          features['channel'] = int((freq - 2412) / 5) + 1
                      elif 5170 <= freq <= 5825: # 5 GHz U-NII bands
                          # Formula for common 5GHz channels (adjust if needed for other regions/bands)
                          if freq == 5000: features['channel'] = 200 # Example special case
                          else: features['channel'] = int((freq - 5000) / 5) # General formula starting point
                      # Add more ranges (4.9GHz, 6GHz etc. if needed)
        except Exception:
            pass # Signal strength or Channel Freq might not be present

        # Extract Beacon Interval and Capabilities (if Beacon/ProbeResp)
        if pkt.haslayer(scapy.Dot11Beacon) or pkt.haslayer(scapy.Dot11ProbeResp):
             layer = pkt.getlayer(scapy.Dot11Beacon) or pkt.getlayer(scapy.Dot11ProbeResp)
             if hasattr(layer, 'beacon_interval'):
                  features['beacon_interval'] = layer.beacon_interval # Time Units (TU), 1 TU = 1024 microseconds
             if hasattr(layer, 'cap') and isinstance(layer.cap, scapy.Dot11Caps):
                if layer.cap.privacy: # Check privacy bit
                    # If RSN/WPA already found, they are more specific
                    if not ('RSN' in features['auth_schemes'] or 'WPA' in features['auth_schemes']):
                         features['auth_schemes'].add('WEP/Other_Enc') # WEP or some other encrypted if no WPA/RSN
                else:
                     # If no encryption bits set and no WPA/RSN found, assume Open
                     if not features['auth_schemes']:
                          features['auth_schemes'].add('Open')

    # Ensure 'Open' isn't present if specific encryption is found
    if 'RSN' in features['auth_schemes'] or 'WPA' in features['auth_schemes'] or 'WEP/Other_Enc' in features['auth_schemes']:
        features['auth_schemes'].discard('Open')

    # Handle case where no auth info found at all
    if not features['auth_schemes']:
        features['auth_schemes'].add("Unknown")


    return features

def packet_handler_profiling(target_ssids):
    """Packet handler for the profiling phase."""
    def handle_packet(pkt):
        # Ensure it's a frame likely containing the info we need (Beacon or Probe Response)
        if not (pkt.haslayer(scapy.Dot11Beacon) or pkt.haslayer(scapy.Dot11ProbeResp)):
             return

        features = get_packet_features(pkt)
        bssid = features['bssid']
        ssid = features['ssid']

        if bssid and ssid and ssid in target_ssids:
            # print(f"Profiling: Found {ssid} ({bssid}), Signal: {features['signal']}, Channel: {features['channel']}, Auth: {features['auth_schemes']}, Interval: {features['beacon_interval']}") # Debug
            if features['signal'] is not None:
                profiling_data_store[bssid]['signals'].append(features['signal'])
            if features['channel'] is not None:
                profiling_data_store[bssid]['channels'].add(features['channel'])
            if features['auth_schemes']:
                 profiling_data_store[bssid]['auths'].update(features['auth_schemes'])
            if features['beacon_interval'] is not None:
                 # Convert TU (1024 us) to ms for consistency with threshold later? Or keep as TU? Let's keep TU for now.
                 profiling_data_store[bssid]['beacons'].append(features['beacon_interval'])
            # Store associated SSID if not already stored
            if profiling_data_store[bssid]['ssid'] is None:
                profiling_data_store[bssid]['ssid'] = ssid

    return handle_packet


def packet_handler_monitoring(target_ssids, whitelist_bssids_map, deauth_callback=None):
    """Packet handler for the monitoring phase."""
    # Get threshold values from config
    beacon_interval_threshold_diff = config['anomaly_thresholds']['beacon_interval_ms_diff']
    # Signal strength threshold usage is commented out below due to reliability issues

    def handle_packet(pkt):
        now = time.time()
        global assoc_state # Use global state for association tracking

        if not pkt.haslayer(scapy.Dot11):
            return

        ap_mac = None
        client_mac = None
        pkt_ssid = None
        pkt_channel = None
        pkt_signal = None

        # --- Basic Identification ---
        ds_status = pkt.FCfield & 0x3 # ToDS/FromDS bits
        addr1 = pkt.addr1 # DA or RA
        addr2 = pkt.addr2 # TA or SA or BSSID
        addr3 = pkt.addr3 # SA or DA or BSSID
        # Determine BSSID based on frame type / DS status
        if pkt.haslayer(scapy.Dot11Beacon) or pkt.haslayer(scapy.Dot11ProbeResp) or pkt.haslayer(scapy.Dot11ATIM) or pkt.haslayer(scapy.Dot11Disas) or pkt.haslayer(scapy.Dot11Auth) or pkt.haslayer(scapy.Dot11Deauth):
             ap_mac = addr2 # BSSID is typically addr2 in these management frames
             client_mac = addr1 # Destination (often broadcast or specific client)
        elif pkt.haslayer(scapy.Dot11AssoReq) or pkt.haslayer(scapy.Dot11ReassoReq) or pkt.haslayer(scapy.Dot11ProbeReq):
             ap_mac = addr1 # AP is Destination (BSSID)
             client_mac = addr2 # Client is Source
        elif pkt.haslayer(scapy.Dot11AssoResp) or pkt.haslayer(scapy.Dot11ReassoResp):
             ap_mac = addr2 # AP is Source (BSSID)
             client_mac = addr1 # Client is Destination
        elif ds_status == 0x1: # Frame To AP (From DS = 0, To DS = 1)
            ap_mac = addr1 # BSSID
            client_mac = addr2 # SA
        elif ds_status == 0x2: # Frame From AP (From DS = 1, To DS = 0)
            ap_mac = addr2 # BSSID
            client_mac = addr1 # DA
        # This logic might still need refinement for all cases, but covers common ones

        # Try extracting SSID and channel from any relevant frame type
        # Reuse get_packet_features for consistency
        extracted_features = get_packet_features(pkt)
        pkt_ssid = extracted_features['ssid']
        pkt_channel = extracted_features['channel']
        pkt_signal = extracted_features['signal']
        # If AP MAC wasn't determined above but features has it, use it
        if ap_mac is None and extracted_features['bssid']:
            ap_mac = extracted_features['bssid']

        # --- 1. Unknown BSSID Check ---
        # Check only if we have an AP MAC, and the packet contains an SSID we care about
        if ap_mac and pkt_ssid and pkt_ssid in target_ssids:
            if ap_mac not in whitelist_bssids_map.get(pkt_ssid, set()):
                # Check if already blacklisted for this reason to avoid spamming
                conn = sqlite3.connect(config['general']['db_name'])
                cursor = conn.cursor()
                cursor.execute("SELECT reason FROM blacklist WHERE bssid=?", (ap_mac,))
                row = cursor.fetchone()
                conn.close()
                if not row or "Unknown BSSID" not in row[0]:
                    add_to_blacklist(ap_mac, pkt_ssid, pkt_channel, "Unknown BSSID for SSID")
                    if deauth_callback:
                        deauth_callback(ap_mac, pkt_channel) # Trigger potential deauth prompt
                return # Don't process anomalies for already blacklisted unknown BSSIDs

        # --- Process only if BSSID is potentially known/whitelisted ---
        # Check if ap_mac is in ANY of the whitelisted sets
        is_whitelisted_bssid = any(ap_mac in bssid_set for bssid_set in whitelist_bssids_map.values())

        if ap_mac and is_whitelisted_bssid:
             baseline = get_baseline(ap_mac)
             if not baseline: return # Should not happen if logic is correct, but safe check

             # --- 2. Anomaly Detection (compare with baseline) ---
             current_features = extracted_features # Use features already extracted

             # Check Channel Anomaly
             if current_features['channel'] is not None and baseline['channel'] is not None and \
                current_features['channel'] != baseline['channel']:
                 add_to_blacklist(ap_mac, baseline['ssid'], current_features['channel'], f"Channel Mismatch (Expected {baseline['channel']}, Got {current_features['channel']})")
                 if deauth_callback: deauth_callback(ap_mac, current_features['channel'])
                 # Potentially stop further checks for this packet if channel is wrong? Or report all anomalies?

             # Check Auth Scheme Anomaly (compare normalized strings)
             current_auths_str = ",".join(sorted(list(current_features['auth_schemes']))).replace('WEP/Other_Enc','Encrypted').replace(',Unknown','') # Normalize
             baseline_auths_str = baseline['auth_schemes'].replace('WEP/Other_Enc','Encrypted').replace(',Unknown','') if baseline['auth_schemes'] else ""
             if current_auths_str and baseline_auths_str and current_auths_str != baseline_auths_str and 'Unknown' not in current_auths_str : # Avoid flagging if current is just unknown
                  add_to_blacklist(ap_mac, baseline['ssid'], current_features['channel'], f"Auth Mismatch (Expected '{baseline_auths_str}', Got '{current_auths_str}')")
                  if deauth_callback: deauth_callback(ap_mac, current_features['channel'])

             # Check Beacon Interval Anomaly (Ensure both are not None)
             # Note: Beacon interval is in TUs (1024 us). Threshold is in ms. Convert for comparison.
             # Threshold is `beacon_interval_ms_diff`. Baseline/Current are TU.
             # Diff (ms) = abs(current_TU - baseline_TU) * 1.024
             if current_features['beacon_interval'] is not None and baseline['beacon_interval'] is not None:
                  interval_diff_ms = abs(current_features['beacon_interval'] - baseline['beacon_interval']) * 1.024
                  if interval_diff_ms > beacon_interval_threshold_diff:
                      add_to_blacklist(ap_mac, baseline['ssid'], current_features['channel'], f"Beacon Interval Anomaly (Expected {baseline['beacon_interval']} TU, Got {current_features['beacon_interval']} TU, Diff ~{interval_diff_ms:.1f}ms)")
                      if deauth_callback: deauth_callback(ap_mac, current_features['channel'])

             # Check Signal Strength Anomaly (Commented out - generally unreliable)
             # signal_strength_threshold_diff = config['anomaly_thresholds']['signal_strength_dbm_diff']
             # if pkt_signal is not None and baseline['avg_signal'] is not None and \
             #    abs(pkt_signal - baseline['avg_signal']) > signal_strength_threshold_diff:
             #     add_to_blacklist(ap_mac, baseline['ssid'], current_features['channel'], f"Signal Strength Anomaly (Baseline avg {baseline['avg_signal']}, Got {pkt_signal})")
             #     if deauth_callback: deauth_callback(ap_mac, current_features['channel'])


        # --- 3. Agarwal et al. Association Response Analysis ---
        if pkt.haslayer(scapy.Dot11AssoReq) and client_mac:
             # Record timestamp of association request from this client
             assoc_state[client_mac]['req_ts'] = now
             assoc_state[client_mac]['resp_info'] = [] # Clear previous responses for this new request

        elif pkt.haslayer(scapy.Dot11AssoResp) and client_mac and ap_mac:
            # Check if this response is for a recent request from the client
            if now - assoc_state[client_mac]['req_ts'] < ASSOC_WINDOW:
                seq_num = pkt[scapy.Dot11].SC >> 4 # Sequence Number (upper 12 bits)
                retry_bit = pkt.FCfield.retry
                aid = pkt[scapy.Dot11AssoResp].AID if hasattr(pkt[scapy.Dot11AssoResp], 'AID') else None # Ensure AID exists
                resp_tuple = (ap_mac, seq_num, retry_bit, aid, pkt_channel) # Include channel

                is_duplicate = False
                is_invalid_retry = False
                offending_ap = ap_mac # The AP sending the current frame

                # Check against already received responses for this request
                for existing_ap, existing_seq, existing_retry, existing_aid, existing_channel in assoc_state[client_mac]['resp_info']:
                    # Rule 1: Two responses from DIFFERENT APs with R=0 and same Seq# -> Evil Twin forgery
                    if resp_tuple[0] != existing_ap and \
                       resp_tuple[1] == existing_seq and \
                       resp_tuple[2] == 0 and existing_retry == 0:
                        is_duplicate = True
                        offending_ap = resp_tuple[0] # Current AP is the offender
                        break
                    # Rule 2: Retry frame (R=1) from one AP doesn't match non-retry (R=0) from another (Seq# or AID) -> Evil Twin forgery
                    if resp_tuple[0] != existing_ap: # Check responses from different APs
                         # Current is Retry (R=1), Existing is Non-Retry (R=0)
                         if resp_tuple[2] == 1 and existing_retry == 0 and \
                            (resp_tuple[1] != existing_seq or (resp_tuple[3] is not None and resp_tuple[3] != existing_aid)):
                              is_invalid_retry = True
                              offending_ap = resp_tuple[0] # Current AP (sending retry) is the offender
                              break
                         # Existing is Retry (R=1), Current is Non-Retry (R=0)
                         if existing_retry == 1 and resp_tuple[2] == 0 and \
                            (resp_tuple[1] != existing_seq or (resp_tuple[3] is not None and resp_tuple[3] != existing_aid)):
                              is_invalid_retry = True
                              offending_ap = existing_ap # Existing AP (that sent retry) is the offender
                              # We might want to blacklist the current one too, as it creates ambiguity
                              break

                if is_duplicate or is_invalid_retry:
                    reason = "Duplicate Association Response (R=0, Same Seq)" if is_duplicate else "Invalid Association Response Retry"
                    involved_aps = {r[0] for r in assoc_state[client_mac]['resp_info']}
                    involved_aps.add(ap_mac)
                    offending_channel = pkt_channel if offending_ap == ap_mac else None
                    # Try to get channel for the other involved AP if needed
                    if not offending_channel:
                        for r in assoc_state[client_mac]['resp_info']:
                            if r[0] == offending_ap:
                                offending_channel = r[4]
                                break

                    print(f"🚨 Association Anomaly Detected involving client {client_mac} and APs: {involved_aps}. Reason: {reason}. Likely offender: {offending_ap}")
                    # Blacklist the likely offending AP
                    add_to_blacklist(offending_ap, pkt_ssid, offending_channel, f"Assoc Anomaly ({reason})")
                    # Optionally blacklist others involved? Could lead to false positives if one AP is legit but slow.
                    # Trigger deauth for the offender
                    if deauth_callback and offending_ap: deauth_callback(offending_ap, offending_channel)


                # Store this response info (including channel)
                assoc_state[client_mac]['resp_info'].append(resp_tuple)

        # --- 4. Deauthentication Frame Monitoring ---
        if pkt.haslayer(scapy.Dot11Deauth) and ap_mac:
            # Check if the source of the deauth is a *whitelisted* BSSID
             if is_whitelisted_bssid: # Use the flag checked earlier
                 baseline = get_baseline(ap_mac) # Get baseline to find SSID/Channel
                 if baseline:
                     print(f"⚠️ WARNING: Deauth frame detected FROM whitelisted BSSID: {ap_mac} (SSID: {baseline['ssid']}) -> Client: {client_mac} on Channel: {pkt_channel or baseline['channel']}")
                     # Thresholding needed here. For now, blacklist immediately.
                     add_to_blacklist(ap_mac, baseline['ssid'], pkt_channel or baseline['channel'], "Anomalous Deauth from Whitelisted AP")
                     # if deauth_callback: deauth_callback(ap_mac, pkt_channel or baseline['channel'])


        # Clean up old association state entries periodically if needed (e.g., in main loop)

    return handle_packet


# --- Deauthentication Attack ---
# (send_deauth function remains the same)
# ... (copy from previous version) ...
def send_deauth(iface, target_bssid, target_client='ff:ff:ff:ff:ff:ff', count=10):
    """Sends deauthentication frames to disrupt connection (USE WITH CAUTION)."""
    print(f"\n☢️ WARNING: Sending {count} deauthentication frames to Client {target_client} via AP {target_bssid} on interface {iface}.")
    print("☢️ This is potentially disruptive and illegal without authorization!")
    try:
        confirm = input("☢️ Proceed? (y/N): ").lower()
    except EOFError: # Handle case where input is piped or unavailable
        print("Non-interactive mode. Assuming NO to deauthentication.")
        confirm = 'n'

    if confirm != 'y':
        print("Deauthentication aborted.")
        return

    # Craft deauth frame targeting the client from the AP
    dot11 = scapy.Dot11(type=0, subtype=12, addr1=target_client, addr2=target_bssid, addr3=target_bssid)
    frame = scapy.RadioTap()/dot11/scapy.Dot11Deauth(reason=7) # Reason 7: Class 3 frame received from nonassociated STA

    print(f"Sending {count} frames...")
    try:
        scapy.sendp(frame, iface=iface, count=count, inter=0.1, verbose=False)
        print("Deauthentication frames sent.")
    except Exception as e:
        print(f"Error sending deauthentication frames: {e}")


# --- Main Execution ---

def run_profiling(iface, target_ssids, duration):
    """Runs the profiling phase."""
    print(f"\n--- Starting Profiling Phase ---")
    print(f"Target SSIDs: {', '.join(target_ssids)}")
    print(f"Sniffing on interface: {iface}")
    print(f"Profiling duration: {duration} seconds")
    print("Capturing baseline data for legitimate APs...")

    channels_to_scan = config['general']['channels_to_scan']
    channel_hop_delay = config['general']['channel_hop_delay']

    if not channels_to_scan:
        print("No channels specified for profiling. Please check your configuration.")
        return
    if channel_hop_delay <= 0:
        print("Invalid channel hop delay specified. Please check your configuration.")
        return

    global profiling_data_store
    profiling_data_store.clear() # Clear previous data

    handler = packet_handler_profiling(target_ssids)
    start_time = time.time()

    try:
        while time.time() - start_time < duration:
            print(f"\nStarting new profiling cycle...")
            for channel in channels_to_scan:
                if time.time() - start_time >= duration:
                    print("Profiling duration reached. Stopping...")
                    break
                set_channel(iface, channel) # Set the channel for sniffing
            if time.time() - start_time >= duration:
                break
        
    except OSError as e:
         print(f"Error sniffing: {e}. Do you have permissions (root)? Is the interface correct ('{iface}') and in monitor mode?")
         return
    except Exception as e:
         print(f"An unexpected error occurred during sniffing: {e}")
         return


    print("\n--- Profiling Complete ---")
    print("Processing collected data...")

    if not profiling_data_store:
        print("No beacon/probe response frames captured for the target SSIDs. Ensure you are in range and the SSIDs are active.")
        return

    for bssid, data in profiling_data_store.items():
        if not data['signals']:
            avg_signal = None
        else:
            avg_signal = round(sum(data['signals']) / len(data['signals'])) if data['signals'] else None


        if not data['channels']:
             profile_channel = None
        elif len(data['channels']) == 1:
             profile_channel = list(data['channels'])[0]
        else:
             # Simple heuristic: use the most frequently seen channel if multiple detected
             channel_counts = defaultdict(int)
             # Need to actually capture channel per packet during profiling for this
             # For now, just take the first one seen as before.
             # TODO: Enhance profiling handler to store channel per packet if needed.
             profile_channel = list(data['channels'])[0]
             print(f"Warning: Multiple channels ({data['channels']}) detected for BSSID {bssid}. Using first seen: {profile_channel}")


        profile_auth = ",".join(sorted(list(data['auths']))) if data['auths'] else "Unknown"

        if not data['beacons']:
            profile_beacon_interval = None
        else:
             # Use average beacon interval (in TU)
             profile_beacon_interval = round(sum(data['beacons']) / len(data['beacons'])) if data['beacons'] else None


        profile = {
            'ssid': data['ssid'], # Get the stored SSID
            'bssid': bssid,
            'channel': profile_channel,
            'avg_signal': avg_signal,
            'auth_schemes': profile_auth,
            'beacon_interval': profile_beacon_interval
        }
        # Only add if core data (ssid, bssid) is present
        if profile['ssid'] and profile['bssid']:
             print(f"Adding to whitelist: {profile}")
             add_to_whitelist(profile)
        else:
             print(f"Skipping whitelist add for {bssid} due to missing SSID or BSSID in profile data.")


    print("Baseline profiles stored in the whitelist.")


def run_monitoring(iface, target_ssids, enable_deauth):
    """Runs the monitoring phase."""
    print(f"\n--- Starting Monitoring Phase ---")
    print(f"Target SSIDs: {', '.join(target_ssids)}")
    print(f"Monitoring interface: {iface}")
    print(f"Automatic Deauth Prompting: {'Enabled' if enable_deauth else 'Disabled'}")

    # Load whitelist for quick lookup
    whitelist_bssids_map = defaultdict(set)
    db_path = config['general']['db_name']
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Ensure target_ssids is not empty before querying
    if target_ssids:
        cursor.execute("SELECT ssid, bssid FROM whitelist WHERE ssid IN ({seq})".format(seq=','.join(['?']*len(target_ssids))), target_ssids)
        for ssid, bssid in cursor.fetchall():
            whitelist_bssids_map[ssid].add(bssid)
    conn.close()

    if not any(whitelist_bssids_map.values()): # Check if any BSSIDs were loaded
        print("Warning: Whitelist is empty or does not contain target SSIDs specified in config.")
        if not target_ssids:
             print("No target SSIDs specified in config for monitoring.")
        # Consider exiting if monitoring is pointless without a baseline
        # return

    print("Whitelisted BSSIDs loaded:")
    if whitelist_bssids_map:
        for ssid, bssids in whitelist_bssids_map.items():
            print(f"  {ssid}: {', '.join(bssids)}")
    else:
        print("  (None loaded for target SSIDs)")


    active_deauth_targets = {} # Store BSSIDs/channels we might deauth {bssid: channel}

    def deauth_prompt_callback(bssid, channel):
        """Callback function to handle potential deauth action."""
        if not enable_deauth:
            return
        # Only prompt if channel is known and not already in the active list
        if bssid and channel and bssid not in active_deauth_targets:
            print("-" * 20)
            print(f"Potential Evil Twin/Compromised AP detected: {bssid} on Channel {channel}")
            active_deauth_targets[bssid] = channel # Mark to avoid repeated prompts immediately

    # --- Main Monitoring Loop ---
    print("Starting packet sniffing for monitoring... Press Ctrl+C to stop.")
    last_blacklist_check = time.time()
    blacklist_check_interval = config['monitoring']['blacklist_check_interval_seconds']
    channel_hop_delay = config['general']['channel_hop_delay_seconds']
    channels_to_scan = config['general']['channels_to_scan']


    handler = packet_handler_monitoring(target_ssids, whitelist_bssids_map, deauth_prompt_callback if enable_deauth else None)

    try:
        if not channels_to_scan:
             print("Error: No channels specified in config 'monitoring.channels_to_scan'. Cannot sniff.")
             return

        while True:
             for channel in channels_to_scan:
                 set_channel(iface, channel)
                 # Sniff for a short duration on each channel
                 scapy.sniff(iface=iface, prn=handler, timeout=channel_hop_delay, store=False)

                 # --- Periodic Tasks within the loop ---
                 current_time = time.time()

                 # Check if user wants to deauth any flagged APs
                 if enable_deauth and active_deauth_targets:
                     print("\n--- Deauth Options ---")
                     targets = list(active_deauth_targets.items())
                     for i, (bssid, chan) in enumerate(targets):
                          print(f"{i+1}. Deauth BSSID: {bssid} (Channel: {chan})")
                     print("Enter number to deauth, 's' to skip/remove, 'q' to quit prompt for now.")
                     try:
                         choice = input("Choice: ").lower()
                     except EOFError:
                         print("Non-interactive mode. Skipping deauth prompt.")
                         choice = 'q' # Assume quit prompt in non-interactive

                     if choice.isdigit() and 1 <= int(choice) <= len(targets):
                          target_bssid, target_channel = targets[int(choice)-1]
                          print(f"Setting channel to {target_channel} for deauth...")
                          set_channel(iface, target_channel)
                          time.sleep(0.5) # Give time for channel change
                          send_deauth(iface, target_bssid)
                          del active_deauth_targets[target_bssid] # Remove from prompt list
                     elif choice == 's':
                          clear_choice = input("Enter number to remove from prompt list, or 'a' for all: ").lower()
                          if clear_choice.isdigit() and 1 <= int(clear_choice) <= len(targets):
                               target_bssid, _ = targets[int(clear_choice)-1]
                               if target_bssid in active_deauth_targets: del active_deauth_targets[target_bssid]
                          elif clear_choice == 'a':
                               active_deauth_targets.clear()
                     elif choice == 'q':
                          pass # Do nothing, will prompt again later
                     else:
                           print("Invalid choice.")


                 # Display blacklist periodically
                 if current_time - last_blacklist_check > blacklist_check_interval:
                      print("\n--- Current Blacklist ---")
                      blacklist = get_blacklist()
                      if not blacklist:
                          print("(empty)")
                      else:
                          for entry in blacklist:
                             # bssid, ssid, channel, reason, first, last
                             print(f"- BSSID: {entry[0]}, SSID: {entry[1] or 'N/A'}, Chan: {entry[2] or '?'}, Reason: {entry[3]}, First: {entry[4]}, Last: {entry[5]}")
                      last_blacklist_check = current_time
                      # Optional: Clean up old association state entries
                      # cutoff = time.time() - (ASSOC_WINDOW * 10) # Example cleanup threshold
                      # keys_to_del = [k for k, v in assoc_state.items() if v['req_ts'] < cutoff]
                      # for k in keys_to_del: del assoc_state[k]

    except KeyboardInterrupt:
        print("\nCtrl+C detected. Stopping monitoring...")
    except OSError as e:
         print(f"Error sniffing: {e}. Do you have permissions (root)? Is the interface correct ('{iface}') and in monitor mode?")
    except Exception as e:
         print(f"An unexpected error occurred during monitoring: {e}")
         import traceback
         traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evil Twin Rogue AP Detector Tool")
    parser.add_argument("mode", choices=['profile', 'monitor'], help="Operation mode: 'profile' (build baseline) or 'monitor' (detect threats)")
    parser.add_argument("-c", "--config", default="config.json", help="Path to the configuration file (default: config.json)")

    if len(sys.argv) == 1 or sys.argv[1] in ['-h', '--help']:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Load Configuration ---
    config = load_config(args.config)

    # --- Initial Setup ---
    if os.geteuid() != 0:
        print("Warning: Script not running as root. May fail to enable monitor mode or sniff packets.")

    init_db() # Initialize DB using name from config
    monitor_iface = None
    original_iface = config['general']['interface']

    try:
        monitor_iface = set_monitor_mode(original_iface, enable=True)
        if not monitor_iface:
             raise RuntimeError(f"Failed to enable monitor mode on {original_iface}. Attempted interface: {monitor_iface}")

        if args.mode == 'profile':
            target_ssids = config['profiling']['target_ssids']
            duration = config['profiling']['duration_seconds']
            if not target_ssids:
                 print("Error: No target SSIDs specified in config file for profiling.")
                 sys.exit(1)
            run_profiling(monitor_iface, target_ssids, duration)
        elif args.mode == 'monitor':
            target_ssids = config['monitoring']['target_ssids']
            enable_deauth = config['monitoring']['enable_deauth_prompt']
            # Run even if target_ssids is empty, might just monitor for general anomalies?
            # Or add a check:
            if not target_ssids:
                 print("Warning: No target SSIDs specified in config file for monitoring.")
                 # Decide if you want to proceed or exit
                 # sys.exit(1)
            run_monitoring(monitor_iface, target_ssids, enable_deauth)

    except Exception as e:
        print(f"An error occurred in main execution: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # --- Cleanup ---
        if monitor_iface:
            print("\nCleaning up: Disabling monitor mode...")
            try:
                 # Use the potentially modified interface name for stopping airmon-ng
                 set_monitor_mode(monitor_iface, enable=False)
            except Exception as e:
                 print(f"Error during cleanup: {e}")
        print("Exiting.")