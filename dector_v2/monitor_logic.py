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

# --- Global State ---
ap_monitor_state = collections.defaultdict(lambda: {
    "recent_rssi": [],
    "last_auth_type": None,
    "last_cipher": None,
    "alert_states": collections.defaultdict(bool),
    "last_alert_time": 0,
})
flagged_aps = {}
baseline_profiles = {}
known_bssids = {}
monitor_config = {}

# --- Constants ---
RSSI_WINDOW = 20
ALERT_COOLDOWN = 60
RSSI_STDEV_THRESH = 10.0
RSSI_RANGE_THRESH = 25.0


def parse_auth_details(privacy, cipher, auth):
    """
    Standardize auth type and cipher.
    """
    base = "Unknown"
    if "OWE" in auth:
        base = "OWE"
    elif "WPA3" in privacy:
        base = "WPA3"
    elif "WPA2" in privacy:
        base = "WPA2"
    elif "WPA" in privacy:
        base = "WPA"
    elif "WEP" in privacy:
        base = "WEP"
    elif "OPN" in privacy:
        base = "OPEN"

    auth_type = base
    if base == "WPA3" and "SAE" in auth:
        auth_type += "-SAE"
    elif base in ("WPA2","WPA") and "PSK" in auth:
        auth_type += "-PSK"
    elif base in ("WPA2","WPA") and "MGT" in auth:
        auth_type += "-EAP"

    final_cipher = "Unknown"
    if "GCMP-256" in cipher:
        final_cipher = "GCMP-256"
    elif "CCMP" in cipher:
        final_cipher = "CCMP"
    elif "TKIP" in cipher:
        final_cipher = "TKIP"
    elif "WEP" in cipher:
        final_cipher = "WEP"
    elif base in ("OPEN","OWE"):
        final_cipher = "None"
    print(auth_type, final_cipher) # For Debug
    return auth_type, final_cipher


def extract_rssi(pkt):
    """Return dBm_AntSignal or None."""
    if not pkt.haslayer(RadioTap):
        return None
    return getattr(pkt[RadioTap], "dBm_AntSignal", None)


def extract_channel(pkt):
    """Return channel number or None."""
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        freq = getattr(rt, "ChannelFrequency", None)
        if freq and 2412 <= freq <= 5825:
            return int((freq - 2412) / 5) + 1
        ch = getattr(rt, "Channel", None) + 1
        if ch and isinstance(ch, int):
            return ch

    for elt in pkt.getlayer(Dot11Elt),:
        if elt.ID == 3 and elt.info:
            return elt.info[0]
    return None


def extract_ssid(pkt):
    """Return SSID string or None."""
    for elt in pkt.getlayer(Dot11Elt),:
        if elt.ID == 0:
            return "<Hidden>" if elt.len == 0 else elt.info.decode(errors="ignore")
    return None


def parse_auth(pkt):
    """Parse auth/cipher from beacon or probe response."""
    privacy = set()
    cipher = set()
    auth = set()

    # print(pkt.getlayer(Dot11Elt)) # for debug

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        # print(elt)  # DEBUG
        if elt.ID == 48:
            privacy.add("WPA2")
        if elt.ID == 221:
            privacy.add("WPA")

        # Walk to next element
        if elt.payload and isinstance(elt.payload, scapy.Packet) and elt.payload.haslayer(Dot11Elt):
            elt = elt.payload.getlayer(Dot11Elt)
        else:
            break

    cap = None
    if pkt.haslayer(Dot11Beacon):
        cap = pkt[Dot11Beacon].cap
    elif pkt.haslayer(Dot11ProbeResp):
        cap = pkt[Dot11ProbeResp].cap

    if cap and getattr(cap, "Privacy", False):
        privacy.add("WEP")

    if not privacy:
        privacy.add("OPN")

    if "WPA3" in privacy:
        auth.update(["SAE"])
        cipher.update(["GCMP-256"])
    elif "WPA2" in privacy:
        auth.update(["PSK"])
        cipher.update(["CCMP", "TKIP"])
    elif "WPA" in privacy:
        auth.update(["PSK"])
        cipher.update(["TKIP"])
    elif "WEP" in privacy:
        cipher.add("WEP")
    return parse_auth_details(privacy, cipher, auth)


def set_channel(iface, channel):
    """Set interface channel, return True on success."""
    try:
        subprocess.run(
            ["iwconfig", iface, "channel", str(channel)],
            check=True, timeout=3
        )
        return True
    except subprocess.CalledProcessError:
        return False


def channel_hopper(iface, stop_evt, channels, dwell):
    """Continuously hop channels until stop_evt is set."""
    idx = 0
    while not stop_evt.is_set():
        set_channel(iface, channels[idx % len(channels)])
        time.sleep(dwell)
        idx += 1


def generate_alert(bssid, ssid, channel, reason, power=None):
    """Print and record an alert."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info = f"BSSID:{bssid}, SSID:'{ssid}', CH:{channel or '?'}, PWR:{power}"
    print(f"ALERT [{ts}] {reason} | {info}")
    flagged_aps[bssid.lower()] = {
        "ssid": ssid,
        "channel": channel,
        "reason": reason,
        "time": ts,
        "power": power,
    }


def scapy_handler(pkt):
    """Handle each sniffed packet, check for anomalies."""
    if not SCAPY_AVAILABLE:
        return

    cfg = monitor_config
    targets = cfg.get("target_ssids", [])
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return

    bssid = pkt[Dot11].addr2.lower()
    ssid = extract_ssid(pkt)
    if ssid not in targets:
        return

    now = pkt.time
    state = ap_monitor_state[bssid]
    baseline_set = known_bssids.get(ssid, set())

    if bssid not in baseline_set:
        if not state["alert_states"]["new_bssid"] and now - state["last_alert_time"] > ALERT_COOLDOWN:
            generate_alert(bssid, ssid, extract_channel(pkt), "Unknown BSSID", extract_rssi(pkt))
            state["alert_states"]["new_bssid"] = True
            state["last_alert_time"] = now
        return

    profile = baseline_profiles.get(bssid, {})
    fired = False

    # Channel mismatch
    ch = extract_channel(pkt)
    exp_ch = profile.get("channel")
    if ch is not None and exp_ch is not None and ch != exp_ch:
        key = "chan_mismatch"
        if not state["alert_states"][key] and now - state["last_alert_time"] > ALERT_COOLDOWN:
            generate_alert(bssid, ssid, ch, f"Channel Mismatch (Exp {exp_ch})", extract_rssi(pkt))
            state["alert_states"][key] = True
            fired = True

    # RSSI spread
    rssi = extract_rssi(pkt)
    if rssi is not None:
        lst = state["recent_rssi"]
        lst.append(rssi)
        state["recent_rssi"] = lst[-RSSI_WINDOW:]
        if len(state["recent_rssi"]) >= 5:
            stdev = statistics.stdev(state["recent_rssi"])
            rng = max(state["recent_rssi"]) - min(state["recent_rssi"])
            if (stdev > RSSI_STDEV_THRESH or rng > RSSI_RANGE_THRESH):
                key = "rssi_spread"
                if not state["alert_states"][key] and now - state["last_alert_time"] > ALERT_COOLDOWN:
                    generate_alert(bssid, ssid, ch, f"RSSI Spread (StDev:{stdev:.1f} Rng:{rng})", rssi)
                    state["alert_states"][key] = True
                    fired = True

    # Auth/cipher mismatch
    auth_type, cipher = parse_auth(pkt)
    exp_auth = profile.get("auth_type")
    exp_cipher = profile.get("cipher")
    if auth_type != exp_auth or cipher != exp_cipher:
        key = "auth_mismatch"
        if not state["alert_states"][key] and now - state["last_alert_time"] > ALERT_COOLDOWN:
            reason = f"Auth Mismatch (Got {auth_type}/{cipher}, Exp {exp_auth}/{exp_cipher})"
            generate_alert(bssid, ssid, ch, reason, rssi)
            state["alert_states"][key] = True
            fired = True

    if fired:
        state["last_alert_time"] = now


def run_monitoring(iface, config, profiles, known):
    """
    Start Scapy-based monitoring with channel hopping.
    """
    if not SCAPY_AVAILABLE:
        print("Error: Scapy not available.")
        return

    global baseline_profiles, known_bssids, monitor_config
    baseline_profiles = profiles
    known_bssids = known
    monitor_config = config.get("monitoring", {})

    channels = config["general"].get("channels_to_scan", [1, 6, 11])
    dwell = monitor_config.get("scan_dwell_seconds", 2)

    stop_evt = threading.Event()
    th = threading.Thread(target=channel_hopper, args=(iface, stop_evt, channels, dwell), daemon=True)
    th.start()

    print("Monitoring... Ctrl+C to stop")
    try:
        scapy.sniff(iface=iface, prn=scapy_handler, store=False,
                    stop_filter=lambda pkt: stop_evt.is_set())
    except Exception as e:
        print(f"Sniff error: {e}")
    finally:
        stop_evt.set()
        th.join()

        if flagged_aps:
            print("\nFlagged APs:")
            for b, d in flagged_aps.items():
                ch = d["channel"] or "?"
                print(f"  {b} SSID:{d['ssid']} CH:{ch} Reason:{d['reason']}")
        print("Monitoring stopped.")
