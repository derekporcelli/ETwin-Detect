#!/usr/bin/env python3
"""
monitor_logic.py

Monitoring logic for AP detection using Scapy.
"""

import collections
import datetime
import os
import signal
import statistics
import subprocess
import sys
import threading
import time

# Conditional Scapy import (in case Scapy is not installed when only profiling)
try:
    import scapy.all as scapy
    from scapy.fields import FlagsField
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11ProbeResp,
        Dot11Elt,
        RadioTap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    print(
        "Warning: Scapy library not found. "
        "Monitoring functionality will not be available."
    )
    scapy = None
    SCAPY_AVAILABLE = False


# --- Global Monitor State Variables (Module Scope) ---
ap_monitor_state = collections.defaultdict(
    lambda: {
        "recent_rssi": [],
        "last_auth_type": None,
        "last_cipher": None,
        "beacon_timestamps": [],
        "alert_states": collections.defaultdict(bool),
        "last_alert_time": 0,
    }
)
flagged_aps = {}
baseline_profiles_global = {}
known_bssids_per_ssid_global = collections.defaultdict(set)
monitor_config_global = {}

# Constants for monitoring state/logic (defaults)
RSSI_WINDOW_SIZE = 20
BEACON_TIME_WINDOW_SIZE = 30
ALERT_COOLDOWN_SEC = 60
RSSI_SPREAD_STDEV_THRESH = 10.0
RSSI_SPREAD_RANGE_THRESH = 25.0


# --- Helper function to parse baseline auth details ---
def parse_auth_details(privacy_set, cipher_set, auth_set):
    """
    Determines standardized Auth Type and Cipher from separate field sets.
    """
    base_type = "Unknown"
    final_auth_type = "Unknown"
    final_cipher = "Unknown"

    if "OWE" in auth_set:
        base_type = "OWE"
    elif "WPA3" in privacy_set:
        base_type = "WPA3"
    elif "WPA2" in privacy_set:
        base_type = "WPA2"
    elif "WPA" in privacy_set:
        if not {"WPA2", "WPA3"}.intersection(privacy_set):
            base_type = "WPA"
    elif "WEP" in privacy_set:
        excluded = {"WPA", "WPA2", "WPA3", "OWE"}
        if not privacy_set.intersection(excluded):
            base_type = "WEP"
    elif "OPN" in privacy_set:
        base_type = "OPEN"

    final_auth_type = base_type

    if base_type == "WPA3":
        if "SAE" in auth_set:
            final_auth_type += "-SAE"
        elif "MGT" in auth_set:
            final_auth_type += "-EAP"
    elif base_type in ("WPA2", "WPA"):
        if "PSK" in auth_set:
            final_auth_type += "-PSK"
        elif "MGT" in auth_set:
            final_auth_type += "-EAP"

    if "GCMP-256" in cipher_set:
        final_cipher = "GCMP-256"
    elif "GCMP-128" in cipher_set:
        final_cipher = "GCMP-128"
    elif "GCMP" in cipher_set:
        final_cipher = "GCMP-256"
    elif "CCMP" in cipher_set:
        final_cipher = "CCMP"
    elif "TKIP" in cipher_set:
        final_cipher = "TKIP"
    elif any(x in cipher_set for x in ("WEP", "WEP40", "WEP104")):
        final_cipher = "WEP"
    elif base_type in ("OPEN", "OWE"):
        final_cipher = "None"

    # Prioritize CCMP over TKIP if both present
    if {"CCMP", "TKIP"}.issubset(cipher_set):
        final_cipher = "CCMP"

    # Fallback guesses
    if final_cipher == "Unknown":
        if final_auth_type.startswith("WPA3"):
            final_cipher = "GCMP-256"
        elif final_auth_type.startswith("WPA2"):
            final_cipher = "CCMP"
        elif final_auth_type.startswith("WPA"):
            final_cipher = "TKIP"
        elif final_auth_type == "WEP":
            final_cipher = "WEP"

    return final_auth_type, final_cipher


# --- Scapy Helper Functions ---
def extract_rssi_scapy(pkt):
    """
    Extracts RSSI from RadioTap header.
    Returns None if not present.
    """
    if not pkt.haslayer(RadioTap):
        return None

    try:
        return pkt[RadioTap].dBm_AntSignal
    except AttributeError:
        print("Debug: dBm_AntSignal not found in RadioTap")
        return None


def extract_channel_scapy(pkt):
    """
    Extracts channel number from RadioTap or Dot11Elt layers.
    Returns None if not found.
    """
    # Try RadioTap frequency field
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]

        # Frequency-to-channel conversion
        if hasattr(rt, "ChannelFrequency"):
            freq = rt.ChannelFrequency
            if 2412 <= freq <= 2484:
                return int((freq - 2412) / 5) + 1
            if 5170 <= freq <= 5825:
                return int((freq - 5000) / 5)

        # Direct channel attribute
        if hasattr(rt, "Channel") and isinstance(rt.Channel, int):
            ch = rt.Channel
            valid_24 = 1 <= ch <= 14
            valid_5 = 36 <= ch <= 173
            if valid_24 or valid_5:
                return ch

    # Fallback: Dot11Elt DS Parameter Set (ID 3)
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3 and hasattr(elt, "info") and elt.info:
                # 'info' is a one-byte channel number
                return elt.info[0]
            if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(
                Dot11Elt
            ):
                elt = elt.payload.getlayer(Dot11Elt)
            else:
                break

    return None


def extract_ssid_scapy(pkt):
    """
    Extracts SSID string from Dot11Elt layers.
    Returns "<Hidden>" if SSID length is zero.
    """
    if not pkt.haslayer(Dot11Elt):
        return None

    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 0 and hasattr(elt, "info"):
            if elt.len == 0:
                return "<Hidden>"
            return elt.info.decode("utf-8", errors="ignore")

        if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(
            Dot11Elt
        ):
            elt = elt.payload.getlayer(Dot11Elt)
        else:
            break

    return None


def parse_auth_scapy(pkt):
    """
    Parses auth details (type, cipher) from a Scapy Dot11Beacon or Dot11ProbeResp pkt.
    Returns (auth_type, cipher).
    """
    privacy_set = set()
    cipher_set = set()
    auth_set = set()
    is_privacy_set = False

    # Parse RSN (ID 48) and WPA vendor IE (ID 221)
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            try:
                if elt.ID == 48:
                    privacy_set.add("WPA2")
                elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                    privacy_set.add("WPA")
            except Exception:
                pass

            if isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(
                Dot11Elt
            ):
                elt = elt.payload.getlayer(Dot11Elt)
            else:
                break

    # Parse capabilities field from Beacon/ProbeResp
    cap_layer = None
    if pkt.haslayer(Dot11Beacon):
        cap_layer = pkt[Dot11Beacon]
    elif pkt.haslayer(Dot11ProbeResp):
        cap_layer = pkt[Dot11ProbeResp]

    if cap_layer and hasattr(cap_layer, "cap"):
        caps = cap_layer.cap
        # Try FlagsField-based attribute
        try:
            if caps.Privacy:
                is_privacy_set = True
                if not privacy_set.intersection({"WPA", "WPA2", "WPA3"}):
                    privacy_set.add("WEP")
        except Exception:
            # Fallback: integer bitmask
            if isinstance(caps, int) and (caps & 0x0010):
                is_privacy_set = True
                if not privacy_set.intersection({"WPA", "WPA2", "WPA3"}):
                    privacy_set.add("WEP")

    if not privacy_set and not is_privacy_set:
        privacy_set.add("OPN")

    # Broad guesses
    if "WPA3" in privacy_set:
        auth_set.update({"SAE", "MGT"})
        cipher_set.update({"GCMP-256"})
    elif "WPA2" in privacy_set:
        auth_set.update({"PSK", "MGT"})
        cipher_set.update({"CCMP", "TKIP"})
    elif "WPA" in privacy_set:
        auth_set.update({"PSK", "MGT"})
        cipher_set.update({"TKIP"})
    elif "WEP" in privacy_set:
        cipher_set.add("WEP")

    # Standardize via parse_auth_details
    auth_type, cipher = parse_auth_details(privacy_set, cipher_set, auth_set)
    return auth_type, cipher


# --- Channel Hopping ---
def set_channel_scapy(iface, channel):
    """
    Sets the wireless interface to the specified channel via iwconfig.
    Returns True on success, False on failure.
    """
    try:
        subprocess.run(
            ["iwconfig", iface, "channel", str(channel)],
            check=True,
            capture_output=True,
            timeout=3,
        )
        return True
    except Exception as e:
        print(f"Warn: Failed to set channel {channel} on {iface}: {e}")
        return False


def channel_hopper(iface, stop_event, channels, dwell_sec):
    """
    Thread target: hops the interface through a list of channels until stop_event is set.
    """
    print("Channel hopper thread started.")
    idx = 0
    while not stop_event.is_set():
        channel = channels[idx % len(channels)]

        set_channel_scapy(iface, channel)

        end_time = time.time() + dwell_sec
        while time.time() < end_time:
            if stop_event.is_set():
                break
            time.sleep(0.1)

        idx += 1

    print("Channel hopper thread stopped.")


# --- Alerting ---
def generate_alert(bssid, ssid, channel, reason, power=None):
    """
    Prints an alert and updates flagged_aps with timestamp and details.
    """
    global flagged_aps

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details = [f"BSSID: {bssid}", f"SSID: '{ssid}'", f"Channel: {channel or '?'}"]
    if power is not None:
        details.append(f"PWR: {power}dBm")

    alert_msg = f"ALERT [{timestamp}] Reason: {reason} | " + ", ".join(details)
    print(alert_msg)

    flagged_aps[bssid.lower()] = {
        "ssid": ssid,
        "channel": channel,
        "reason": reason,
        "last_alert_time": timestamp,
        "last_power": power,
    }


# --- Monitoring Packet Handler ---
def scapy_monitor_handler(pkt):
    """
    Packet handler callback for Scapy sniff().
    Performs anomaly checks against baseline_profiles_global.
    """
    global ap_monitor_state
    global baseline_profiles_global
    global known_bssids_per_ssid_global
    global monitor_config_global

    if not SCAPY_AVAILABLE:
        return

    # Load thresholds from global config
    rssi_stdev_thresh = monitor_config_global.get(
        "rssi_spread_stdev_threshold", RSSI_SPREAD_STDEV_THRESH
    )
    rssi_range_thresh = monitor_config_global.get(
        "rssi_spread_range_threshold", RSSI_SPREAD_RANGE_THRESH
    )
    alert_cooldown = monitor_config_global.get(
        "alert_cooldown_seconds", ALERT_COOLDOWN_SEC
    )
    target_ssids = monitor_config_global.get("target_ssids", [])

    # Only process Beacon/ProbeResp frames
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return

    obs_bssid = None
    if pkt.haslayer(Dot11):
        obs_bssid = pkt[Dot11].addr2

    if not obs_bssid:
        return

    obs_bssid = obs_bssid.lower()
    current_time = getattr(pkt, "time", time.time())

    obs_ssid = extract_ssid_scapy(pkt)
    obs_rssi = extract_rssi_scapy(pkt)
    obs_channel = extract_channel_scapy(pkt)

    if obs_ssid not in target_ssids:
        return

    state = ap_monitor_state[obs_bssid]
    baseline_set = known_bssids_per_ssid_global.get(obs_ssid, set())

    # Check 1: Different BSSID for known SSID
    if obs_bssid not in baseline_set:
        key = "diff_bssid"
        last_alert = state.get("last_alert_time", 0)
        if not state["alert_states"][key] and (current_time - last_alert) > alert_cooldown:
            generate_alert(
                obs_bssid,
                obs_ssid,
                obs_channel,
                "Different BSSID (Potential Evil Twin)",
                obs_rssi,
            )
            state["alert_states"][key] = True
            state["last_alert_time"] = current_time
        return

    # Check 2–n: Known BSSID anomalies
    if obs_bssid in baseline_profiles_global:
        base = baseline_profiles_global[obs_bssid]
        alert_fired = False

        # Channel mismatch
        key = "channel_mismatch"
        expected = base.get("channel")
        if obs_channel is not None and expected is not None:
            if obs_channel != expected:
                last_alert = state.get("last_alert_time", 0)
                if not state["alert_states"][key] and (current_time - last_alert) > alert_cooldown:
                    reason = f"Channel Mismatch (Expected {expected})"
                    generate_alert(obs_bssid, obs_ssid, obs_channel, reason, obs_rssi)
                    state["alert_states"][key] = True
                    alert_fired = True
            else:
                state["alert_states"][key] = False

        # RSSI spread anomaly
        key = "rssi_spread"
        if obs_rssi is not None:
            state["recent_rssi"].append(obs_rssi)
            state["recent_rssi"] = state["recent_rssi"][-RSSI_WINDOW_SIZE:]

            if len(state["recent_rssi"]) >= 5:
                stdev = statistics.stdev(state["recent_rssi"])
                rng = max(state["recent_rssi"]) - min(state["recent_rssi"])
                if stdev > rssi_stdev_thresh or rng > rssi_range_thresh:
                    last_alert = state.get("last_alert_time", 0)
                    if not state["alert_states"][key] and (current_time - last_alert) > alert_cooldown:
                        reason = f"RSSI Spread Anomaly (StDev:{stdev:.1f} Range:{rng:.0f}dBm)"
                        generate_alert(obs_bssid, obs_ssid, obs_channel, reason, obs_rssi)
                        state["alert_states"][key] = True
                        alert_fired = True
                else:
                    state["alert_states"][key] = False

        # Auth detail anomalies
        auth_type, cipher = parse_auth_scapy(pkt)
        base_auth = base.get("auth_type")
        base_cipher = base.get("cipher")

        # Mismatch vs baseline
        key = "auth_mismatch"
        if auth_type != base_auth or cipher != base_cipher:
            last_alert = state.get("last_alert_time", 0)
            if not state["alert_states"][key] and (current_time - last_alert) > alert_cooldown:
                reason = (
                    f"Auth Detail Mismatch (Got {auth_type}/{cipher}, "
                    f"Exp {base_auth}/{base_cipher})"
                )
                generate_alert(obs_bssid, obs_ssid, obs_channel, reason, obs_rssi)
                state["alert_states"][key] = True
                alert_fired = True
        else:
            state["alert_states"][key] = False

        # Inconsistency vs last seen
        key = "auth_inconsistent"
        last_auth = state.get("last_auth_type")
        last_cipher = state.get("last_cipher")
        if last_auth and (auth_type != last_auth or cipher != last_cipher):
            last_alert = state.get("last_alert_time", 0)
            if not state["alert_states"][key] and (current_time - last_alert) > alert_cooldown:
                reason = (
                    f"Inconsistent Auth Seen (Prev: {last_auth}/{last_cipher}, "
                    f"Now: {auth_type}/{cipher})"
                )
                generate_alert(obs_bssid, obs_ssid, obs_channel, reason, obs_rssi)
                state["alert_states"][key] = True
                alert_fired = True
        else:
            # Reset inconsistency alert if now matches baseline
            if auth_type == base_auth and cipher == base_cipher:
                state["alert_states"][key] = False

        # Update last seen auth details
        state["last_auth_type"] = auth_type
        state["last_cipher"] = cipher

        # If any alert fired, update last_alert_time
        if alert_fired:
            state["last_alert_time"] = current_time


def run_monitoring(iface, config_dict, baseline_profiles_dict, known_bssids_dict):
    """
    Runs the monitoring phase using Scapy and baseline comparison.
    """
    if not SCAPY_AVAILABLE:
        print("Error: Scapy library not found.")
        return

    # Populate module-level globals
    global baseline_profiles_global
    global known_bssids_per_ssid_global
    global monitor_config_global

    baseline_profiles_global = baseline_profiles_dict
    known_bssids_per_ssid_global = known_bssids_dict
    monitor_config_global = config_dict.get("monitoring", {})

    print("\n--- Starting Monitoring Phase (Scapy) ---")
    print(f"Interface: {iface}")

    if not monitor_config_global.get("target_ssids"):
        print("Error: No target SSIDs specified for monitoring.")
        return

    if baseline_profiles_global is None:
        print("Error: Baseline profiles not loaded.")
        return

    channels = config_dict.get("general", {}).get("channels_to_scan", [1, 6, 11])
    dwell = monitor_config_global.get("scan_dwell_seconds", 2)

    stop_event = threading.Event()
    hopper = threading.Thread(
        target=channel_hopper,
        args=(iface, stop_event, channels, dwell),
        daemon=True,
    )
    hopper.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    try:
        scapy.sniff(
            iface=iface,
            prn=scapy_monitor_handler,
            stop_filter=lambda pkt: stop_event.is_set(),
            store=False,
        )
    except PermissionError:
        print(f"Error: Permission denied sniffing on {iface}.")
    except OSError as e:
        print(f"Error sniffing on {iface}: {e}")
    except Exception as e:
        print(f"\nError during Scapy sniffing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Stopping monitor threads (may take a moment)...")
        stop_event.set()
        hopper.join(timeout=2)

        if flagged_aps:
            print("\n--- Final Flagged APs ---")
            for bssid, data in flagged_aps.items():
                ch = data["channel"] or "?"
                print(f"  BSSID: {bssid}, SSID: '{data['ssid']}', CH: {ch}, Reason: {data['reason']}")
            print("------------------------\n")

        print("Scapy monitoring stopped.")
