# monitor_logic.py
#!/usr/bin/env python3

import subprocess
import time
import os
import sys
import threading
import signal
import statistics
import datetime
import sqlite3
from collections import defaultdict

# Conditional Scapy import (in case Scapy is not installed when only profiling)
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
except ImportError:
    print("Warning: Scapy not found. Monitoring functionality will not be available.")
    scapy = None # Set to None if not found

# --- Global Monitor State Variables (Module Scope) ---
# These are specific to the monitoring process when it runs
ap_monitor_state = defaultdict(lambda: {
    'recent_rssi': [], 'last_auth_type': None, 'last_cipher': None,
    'beacon_timestamps': [], 'alert_states': defaultdict(bool),
    'last_alert_time': 0
})
flagged_aps = {}
baseline_profiles_global = {}
known_bssids_per_ssid_global = defaultdict(set)
monitor_config_global = {} # To store relevant monitoring config subsections

# Constants for monitoring state/logic
RSSI_WINDOW_SIZE = 20
BEACON_TIME_WINDOW_SIZE = 30
ALERT_COOLDOWN_SEC = 60 # Default, could be overridden by config

# --- Scapy Helper Functions ---
# (Copied from previous combined script: extract_rssi_scapy, extract_channel_scapy, extract_ssid_scapy, parse_auth_scapy)
# Need parse_auth_details as well for parse_auth_scapy internal call
def parse_auth_details(privacy_set, cipher_set, auth_set):
    """Determines standardized Auth Type and Cipher from separate field sets."""
    # (Keep implementation from previous version)
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

def extract_rssi_scapy(pkt):
    if pkt.haslayer(RadioTap): try: return pkt[RadioTap].dBm_AntSignal; except AttributeError: return None
    return None

def extract_channel_scapy(pkt):
    if pkt.haslayer(RadioTap):
        try: freq = pkt[RadioTap].ChannelFrequency;
        if 2412 <= freq <= 2484: return int((freq - 2412) / 5) + 1;
        elif 5170 <= freq <= 5825: return int((freq - 5000) / 5);
        except AttributeError: pass
        try:
             if hasattr(pkt[RadioTap], 'Channel') and isinstance(pkt[RadioTap].Channel, int): return pkt[RadioTap].Channel
        except AttributeError: pass
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt);
        while elt:
            try:
                if elt.ID == 3 and hasattr(elt, 'info') and len(elt.info) > 0: return int(ord(elt.info[:1]))
            except: pass
            if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(Dot11Elt): elt = elt.payload.getlayer(Dot11Elt)
            else: break
    return None

def extract_ssid_scapy(pkt):
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt);
        while elt:
            try:
                if elt.ID == 0 and hasattr(elt, 'info'): return "<Hidden>" if elt.len == 0 else elt.info.decode('utf-8', errors='ignore')
            except: pass
            if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(Dot11Elt): elt = elt.payload.getlayer(Dot11Elt)
            else: break
    return None

def parse_auth_scapy(pkt):
    """Parses auth details (type, cipher) from Scapy packet layers."""
    privacy_set = set(); cipher_set = set(); auth_set = set(); is_privacy_set = False

    # 1. Check RSN/WPA Elements (remains the same)
    if pkt.haslayer(scapy.Dot11Elt):
        elt = pkt.getlayer(scapy.Dot11Elt)
        while elt:
            try:
                if elt.ID == 48: privacy_set.add("WPA2"); # Basic RSN check
                elif elt.ID == 221 and hasattr(elt, 'info') and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'): privacy_set.add("WPA")
            except: pass
            if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(scapy.Dot11Elt): elt = elt.payload.getlayer(scapy.Dot11Elt)
            else: break

    # 2. Check Beacon/ProbeResp Capabilities field
    cap_layer = None
    if pkt.haslayer(scapy.Dot11Beacon): cap_layer = pkt[scapy.Dot11Beacon]
    elif pkt.haslayer(scapy.Dot11ProbeResp): cap_layer = pkt[scapy.Dot11ProbeResp]

    if cap_layer and hasattr(cap_layer, 'cap') and cap_layer.cap is not None:
        try:
            caps = cap_layer.cap # Get the capabilities object/value

            # *** CORRECTED LOGIC ***
            # Directly access the 'Privacy' flag attribute
            # This usually works if Scapy dissected it into a FlagsField enabled object
            if caps.Privacy:
                is_privacy_set = True
                # If privacy bit on, but no WPA/RSN found yet, assume WEP
                if not ("WPA" in privacy_set or "WPA2" in privacy_set or "WPA3" in privacy_set):
                    privacy_set.add("WEP")
            # else: # Privacy bit is off - logic below handles OPN if needed

        except AttributeError:
            # Fallback: If '.Privacy' attribute doesn't exist, maybe 'cap' is an integer?
            # Check Scapy source/docs for the correct bitmask for Privacy (0x0010)
            privacy_mask = 0x0010
            if isinstance(caps, int) and (caps & privacy_mask):
                 is_privacy_set = True
                 if not ("WPA" in privacy_set or "WPA2" in privacy_set or "WPA3" in privacy_set):
                      privacy_set.add("WEP")
            # else: print(f"Debug: Could not access .Privacy attribute or check bitmask on caps: {caps}") # Optional debug
        except Exception as e:
            print(f"Debug: Error parsing capabilities field '{cap_layer.cap}': {e}") # Keep general error catch

    # 3. Determine final type if nothing else found
    if not privacy_set and not is_privacy_set:
        privacy_set.add("OPN")

    # 4. Use the main parsing logic to determine final strings
    # (This part might need further refinement based on deeper RSN parsing if implemented)
    if "WPA3" in privacy_set: auth_set.update(["SAE", "MGT"]); cipher_set.update(["GCMP-256"])
    elif "WPA2" in privacy_set: auth_set.update(["PSK", "MGT"]); cipher_set.update(["CCMP", "TKIP"])
    elif "WPA" in privacy_set: auth_set.update(["PSK", "MGT"]); cipher_set.update(["TKIP"])
    elif "WEP" in privacy_set: cipher_set.add("WEP")

    auth_type, cipher = parse_auth_details(privacy_set, cipher_set, auth_set) # Reuse main parser
    return auth_type, cipher

# --- Channel Hopping ---
def set_channel_scapy(iface, channel):
    """Sets the channel using iwconfig."""
    # Consider adding error logging if needed
    try: subprocess.run(['iwconfig', iface, 'channel', str(channel)], check=True, capture_output=True, timeout=3); return True
    except Exception: return False

def channel_hopper(iface, stop_event, channels, dwell_sec):
    """Thread function to hop channels."""
    print("Channel hopper thread started."); idx = 0
    while not stop_event.is_set():
        channel = channels[idx % len(channels)]
        set_channel_scapy(iface, channel)
        # Sleep for dwell time, checking stop_event periodically
        for _ in range(int(dwell_sec * 10)):
             if stop_event.is_set(): break; time.sleep(0.1)
        idx += 1
    print("Channel hopper thread stopped.")

# --- Alerting ---
def generate_alert(bssid, ssid, channel, reason, power=None):
    """Generates an alert message and adds/updates the flagged AP list."""
    # Accessing global flagged_aps dictionary defined in this module
    global flagged_aps
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details = f"BSSID: {bssid}, SSID: '{ssid}', Channel: {channel or '?'}"
    if power is not None: details += f", PWR: {power}dBm"
    alert_msg = f"ALERT [{timestamp}] Reason: {reason} | {details}"
    print(alert_msg)
    flagged_aps[bssid.lower()] = { 'ssid': ssid, 'channel': channel, 'reason': reason, 'last_alert_time': timestamp, 'last_power': power }

# --- Monitoring Packet Handler (Scapy) ---
def scapy_monitor_handler(pkt):
    """Packet handler for Scapy-based monitoring."""
    # Accessing global state and config specific to monitoring
    global ap_monitor_state, baseline_profiles_global, known_bssids_per_ssid_global, monitor_config_global, flagged_aps

    if scapy is None: return # Do nothing if Scapy wasn't imported

    # Use values from the monitoring config stored in the global dict
    rssi_spread_stdev_thresh = monitor_config_global.get('rssi_spread_stdev_threshold', RSSI_SPREAD_STDEV_THRESH)
    rssi_spread_range_thresh = monitor_config_global.get('rssi_spread_range_threshold', RSSI_SPREAD_RANGE_THRESH)
    alert_cooldown = monitor_config_global.get('alert_cooldown_seconds', ALERT_COOLDOWN_SEC)
    target_ssids_monitor = monitor_config_global.get('target_ssids', [])

    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)): return
    obs_bssid = pkt[Dot11].addr2.lower() if pkt.haslayer(Dot11) else None;
    if not obs_bssid: return
    current_time = time.time(); obs_ssid = extract_ssid_scapy(pkt); obs_rssi = extract_rssi_scapy(pkt); obs_channel = extract_channel_scapy(pkt)

    if obs_ssid in target_ssids_monitor:
        baseline_bssids_for_ssid = known_bssids_per_ssid_global.get(obs_ssid, set()); state = ap_monitor_state[obs_bssid]
        if obs_bssid not in baseline_bssids_for_ssid: # Check 1: Different BSSID
            if not state['alert_states']['diff_bssid'] and (current_time - state['last_alert_time'] > alert_cooldown):
                 generate_alert(obs_bssid, obs_ssid, obs_channel, "Different BSSID", obs_rssi); state['alert_states']['diff_bssid'] = True; state['last_alert_time'] = current_time
            return
        if obs_bssid in baseline_profiles_global: # Check 2: Known BSSID anomalies
            baseline = baseline_profiles_global[obs_bssid]; alert_triggered = False
            # Channel Check
            if obs_channel is not None and baseline.get('channel') is not None and obs_channel != baseline['channel']:
                if not state['alert_states']['channel'] and (current_time - state['last_alert_time'] > alert_cooldown): generate_alert(obs_bssid, obs_ssid, obs_channel, f"Channel Mismatch (Expected {baseline['channel']})", obs_rssi); state['alert_states']['channel'] = True; alert_triggered = True
            else: state['alert_states']['channel'] = False
            # RSSI Check
            if obs_rssi is not None:
                state['recent_rssi'].append(obs_rssi); state['recent_rssi'] = state['recent_rssi'][-RSSI_WINDOW_SIZE:]
                if len(state['recent_rssi']) >= 5:
                    rssi_stdev = statistics.stdev(state['recent_rssi']) if len(state['recent_rssi']) >= 2 else 0.0; rssi_range = max(state['recent_rssi']) - min(state['recent_rssi'])
                    if rssi_stdev > rssi_spread_stdev_thresh or rssi_range > rssi_spread_range_thresh:
                         if not state['alert_states']['rssi_spread'] and (current_time - state['last_alert_time'] > alert_cooldown): generate_alert(obs_bssid, obs_ssid, obs_channel, f"RSSI Spread Anomaly (StDev:{rssi_stdev:.1f} Range:{rssi_range:.0f}dBm)", obs_rssi); state['alert_states']['rssi_spread'] = True; alert_triggered = True
                    else: state['alert_states']['rssi_spread'] = False
            # Auth Check
            current_auth_type, current_cipher = parse_auth_scapy(pkt); baseline_auth = baseline.get('auth_type'); baseline_cipher = baseline.get('cipher')
            if (current_auth_type != baseline_auth or current_cipher != baseline_cipher): # Mismatch vs Baseline
                 if not state['alert_states']['auth_mismatch'] and (current_time - state['last_alert_time'] > alert_cooldown): generate_alert(obs_bssid, obs_ssid, obs_channel, f"Auth Mismatch (Got {current_auth_type}/{current_cipher}, Exp {baseline_auth}/{baseline_cipher})", obs_rssi); state['alert_states']['auth_mismatch'] = True; alert_triggered = True
            else: state['alert_states']['auth_mismatch'] = False
            if state['last_auth_type'] is not None and (current_auth_type != state['last_auth_type'] or current_cipher != state['last_cipher']): # Inconsistency vs Last Seen
                  if not state['alert_states']['auth_inconsistent'] and (current_time - state['last_alert_time'] > alert_cooldown): generate_alert(obs_bssid, obs_ssid, obs_channel, f"Inconsistent Auth Seen (Prev: {state['last_auth_type']}/{state['last_cipher']}, Now: {current_auth_type}/{current_cipher})", obs_rssi); state['alert_states']['auth_inconsistent'] = True; alert_triggered = True
            else: state['alert_states']['auth_inconsistent'] = False
            state['last_auth_type'] = current_auth_type; state['last_cipher'] = current_cipher
            # Update last alert time
            if alert_triggered: state['last_alert_time'] = current_time
            # TODO: Add Beacon Rate check using baseline['avg_beacon_rate'] and timestamps


# --- Main Monitoring Function (Exported) ---
def run_monitoring(iface, config_dict, baseline_profiles_dict, known_bssids_dict):
    """Runs the monitoring phase using Scapy and baseline comparison."""
    # Make sure Scapy is available
    if scapy is None:
        print("Error: Scapy library not found. Cannot run monitoring.")
        return

    # Populate module-level globals needed by the handler/helpers
    global baseline_profiles_global, known_bssids_per_ssid_global, monitor_config_global
    baseline_profiles_global = baseline_profiles_dict
    known_bssids_per_ssid_global = known_bssids_dict
    monitor_config_global = config_dict.get('monitoring', {}) # Store relevant config section

    print(f"\n--- Starting Monitoring Phase (Scapy) ---"); print(f"Interface: {iface}")
    if not monitor_config_global.get('target_ssids'): print("Error: No target SSIDs for monitoring."); return
    if baseline_profiles_global is None: print("Failed to load baseline profiles."); return

    channels_to_scan = config_dict.get('general', {}).get('channels_to_scan', [1,6,11])
    dwell_seconds = monitor_config_global.get('scan_dwell_seconds', 2)

    stop_event = threading.Event()
    hopper = threading.Thread(target=channel_hopper, args=(iface, stop_event, channels_to_scan, dwell_seconds), daemon=True)
    hopper.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    try:
        scapy.sniff(iface=iface, prn=scapy_monitor_handler, stop_filter=lambda x: stop_event.is_set(), store=False)
    except PermissionError: print(f"Error: Permission denied sniffing on {iface}.")
    except OSError as e: print(f"Error sniffing on {iface}: {e}.")
    # Note: KeyboardInterrupt is caught in the main script now
    except Exception as e: print(f"\nError during Scapy sniffing: {e}"); import traceback; traceback.print_exc()
    finally:
        print("Stopping monitor threads (Scapy may take a moment)..."); stop_event.set()
        if hopper.is_alive(): hopper.join(timeout=2);
        # Display final flagged APs
        if flagged_aps:
             print("\n--- Final Flagged APs ---")
             for fbssid, fdata in flagged_aps.items(): print(f"  BSSID: {fbssid}, SSID: '{fdata['ssid']}', CH: {fdata['channel'] or '?'}, Reason: {fdata['reason']}")
             print("------------------------\n")
        print("Scapy monitoring stopped.")