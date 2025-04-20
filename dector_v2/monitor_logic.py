#!/usr/bin/env python3
"""
monitor_logic.py

Monitoring logic for AP anomaly detection using Scapy.
"""

import collections
import datetime
import subprocess
import threading
import time
import statistics

# Conditional Scapy import
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
    )
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not found — monitoring disabled.")
    scapy = None
    SCAPY_AVAILABLE = False

# --- Global State ---
ap_monitor_state = collections.defaultdict(lambda: {
    "recent_rssi": [],
    "beacon_timestamps": [],
    "last_auth_type": None,
    "last_cipher": None,
    "alert_states": collections.defaultdict(bool),
    "last_alert_time": 0,
})
flagged_aps                   = {}
baseline_profiles_global      = {}
known_bssids_per_ssid_global  = {}
monitor_config_global         = {}

# --- Default Thresholds (used if config missing) ---
RSSI_STDEV_THRESH_DEFAULT       = 10.0
RSSI_RANGE_THRESH_DEFAULT       = 25.0
RSSI_ABS_THRESH_DEFAULT         = 20.0
BEACON_PCT_THRESH_DEFAULT       = 50.0
ALERT_COOLDOWN_DEFAULT          = 5
BEACON_WINDOW_SECONDS_DEFAULT   = 30
BEACON_RATE_CHECK_INTERVAL      = 10
RSSI_WINDOW_DEFAULT             = 20


def extract_rssi(pkt):
    """
    Return the dBm_AntSignal from RadioTap, or None if missing.
    """
    if not pkt.haslayer(RadioTap):
        return None

    return getattr(pkt[RadioTap], "dBm_AntSignal", None)


def extract_channel(pkt):
    """
    Extract the Wi-Fi channel from a beacon or probe response frame.

    Priority:
    1. DS Parameter Set (Tag ID 3) — used by airodump-ng
    2. Fallback to RadioTap frequency if necessary
    """

    # First try DS Parameter Set (ID 3)
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3 and elt.len == 1:
                return elt.info[0]  # One-byte channel number
            elt = elt.payload.getlayer(Dot11Elt)

    # Fallback: RadioTap frequency → channel mapping
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        freq = getattr(rt, "ChannelFrequency", None)
        if freq:
            if 2412 <= freq <= 2484:  # 2.4 GHz band
                return int((freq - 2412) / 5) + 1
            elif 5000 <= freq <= 5900:  # 5 GHz band (approximate)
                return int((freq - 5000) / 5)

    return None



def extract_ssid(pkt):
    """
    Return SSID string (or "<Hidden>"), or None if missing.
    """
    if not pkt.haslayer(Dot11Elt):
        return None

    elt = pkt.getlayer(Dot11Elt)

    while elt:
        if elt.ID == 0:
            if elt.len == 0:
                return "<Hidden>"
            return elt.info.decode("utf-8", errors="ignore")

        if (
            elt.payload
            and isinstance(elt.payload, scapy.Packet)
            and elt.payload.haslayer(Dot11Elt)
        ):
            elt = elt.payload.getlayer(Dot11Elt)
        else:
            break

    return None


def generate_alert(bssid, ssid, channel, reason, power=None):
    """
    Print an alert and record it in flagged_aps.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info = f"BSSID:{bssid}, SSID:'{ssid}', CH:{channel or '?'}, PWR:{power}"
    print(f"ALERT [{timestamp}] {reason} | {info}")

    flagged_aps[bssid.lower()] = {
        "ssid": ssid,
        "channel": channel,
        "reason": reason,
        "time": timestamp,
        "power": power,
    }


def parse_auth_details(privacy_set, cipher_set, auth_set):
    """
    From raw sets, standardize to (auth_type, cipher).
    """
    base = "Unknown"

    if "OWE" in auth_set:
        base = "OWE"
    elif "WPA3" in privacy_set:
        base = "WPA3"
    elif "WPA2" in privacy_set:
        base = "WPA2"
    elif "WPA" in privacy_set:
        base = "WPA"
    elif "WEP" in privacy_set:
        base = "WEP"
    elif "OPN" in privacy_set:
        base = "OPEN"

    auth_type = base

    if base == "WPA3" and "SAE" in auth_set:
        auth_type += "-SAE"

    if base in ("WPA2", "WPA"):
        if "PSK" in auth_set:
            auth_type += "-PSK"
        elif "MGT" in auth_set:
            auth_type += "-EAP"

    cipher = "Unknown"

    if "GCMP-256" in cipher_set:
        cipher = "GCMP-256"
    elif "GCMP-128" in cipher_set:
        cipher = "GCMP-128"
    elif "CCMP" in cipher_set:
        cipher = "CCMP"
    elif "TKIP" in cipher_set:
        cipher = "TKIP"
    elif "WEP" in cipher_set:
        cipher = "WEP"
    elif base in ("OPEN", "OWE"):
        cipher = "None"

    return auth_type, cipher


def parse_auth(pkt):
    """
    Extract raw privacy/cipher/auth sets from IEs & caps,
    then call parse_auth_details().
    """
    privacy = set()
    cipher = set()
    auth   = set()

    elt = pkt.getlayer(Dot11Elt)

    while elt:
        if elt.ID == 48:
            privacy.add("WPA2")

        if elt.ID == 221:
            privacy.add("WPA")

        if (
            elt.payload
            and isinstance(elt.payload, scapy.Packet)
            and elt.payload.haslayer(Dot11Elt)
        ):
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
        auth.add("SAE")
        cipher.add("GCMP-256")
    elif "WPA2" in privacy:
        auth.add("PSK")
        cipher.update({"CCMP", "TKIP"})
    elif "WPA" in privacy:
        auth.add("PSK")
        cipher.add("TKIP")
    elif "WEP" in privacy:
        cipher.add("WEP")

    return parse_auth_details(privacy, cipher, auth)


def channel_hopper(iface, stop_evt, channels, dwell):
    """
    Simple thread to hop channels until stop_evt is set.
    """
    idx = 0

    while not stop_evt.is_set():
        subprocess.run(
            ["iwconfig", iface, "channel", str(channels[idx % len(channels)])]
        )

        time.sleep(dwell)
        idx += 1

# Beacon Rate check helper function
def check_beacon_rate(state, bssid, ssid, ch, now, rssi, baseline, cfg):
    """
    Check for beacon-rate anomalies every N seconds.
    Uses a sliding time window.
    """
    window              = cfg.get("beacon_time_window", BEACON_WINDOW_SECONDS_DEFAULT)
    rate_interval       = cfg.get("beacon_rate_check_interval", 10)
    beacon_pct          = cfg.get("beacon_rate_threshold_percent", BEACON_PCT_THRESH_DEFAULT)
    cooldown            = cfg.get("alert_cooldown_seconds", ALERT_COOLDOWN_DEFAULT)
    last_check          = state.get("last_beacon_rate_check", None)

    # Add current timestamp to beacon history
    state["beacon_timestamps"].append(now)
    state["beacon_timestamps"] = [
        ts for ts in state["beacon_timestamps"] if (now - ts) <= window
    ]

    # Skip on first encounter or too soon
    if last_check is None:
        state["last_beacon_rate_check"] = now
        return

    if now - last_check < rate_interval:
        return

    state["last_beacon_rate_check"] = now

    base_rate = baseline.get("avg_beacon_rate")
    if not base_rate or base_rate <= 0:
        return

    current_rate = len(state["beacon_timestamps"]) / window
    pct_diff = abs(current_rate - base_rate) / base_rate * 100
    key = "beacon_rate"
    last_alert = state["last_alert_time"]

    if pct_diff > beacon_pct:
        if not state["alert_states"][key] and (now - last_alert) > cooldown:
            generate_alert(
                bssid,
                ssid,
                ch,
                f"Beacon-Rate Δ {pct_diff:.0f}% > {beacon_pct}%",
                rssi
            )
            state["alert_states"][key] = True
            state["last_alert_time"] = now
    else:
        state["alert_states"][key] = False


def scapy_monitor_handler(pkt):
    """
    Packet handler for Scapy sniff() — performs all anomaly checks
    using thresholds from monitor_config_global, including batched
    beacon‑rate checks every N seconds.
    """
    if not SCAPY_AVAILABLE:
        return

    cfg           = monitor_config_global
    targets       = cfg.get("target_ssids", [])
    thresh_stdev  = cfg.get("rssi_spread_stdev_threshold", RSSI_STDEV_THRESH_DEFAULT)
    thresh_range  = cfg.get("rssi_spread_range_threshold", RSSI_RANGE_THRESH_DEFAULT)
    abs_thresh    = cfg.get("rssi_threshold_dbm_abs", RSSI_ABS_THRESH_DEFAULT)
    cooldown      = cfg.get("alert_cooldown_seconds", ALERT_COOLDOWN_DEFAULT)

    # Only handle Beacon or ProbeResp frames
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return

    # Extract BSSID
    if not pkt.haslayer(Dot11):
        return

    bssid = pkt[Dot11].addr2
    if not bssid:
        return

    bssid = bssid.lower()
    now   = pkt.time

    # SSID filter
    ssid = extract_ssid(pkt)
    if ssid not in targets:
        return

    state    = ap_monitor_state[bssid]
    baseline = baseline_profiles_global.get(bssid)
    known    = known_bssids_per_ssid_global.get(ssid, set())

    # 1) Unknown‐BSSID check
    if bssid not in known:
        last = state["last_alert_time"]
        key  = "new_bssid"
        if (now - last) > cooldown:
            state["alert_states"][key] = False
        if not state["alert_states"][key]:
            generate_alert(
                bssid,
                ssid,
                extract_channel(pkt),
                "Different BSSID (Potential Evil Twin)",
                extract_rssi(pkt)
            )
            state["alert_states"][key]     = True
            state["last_alert_time"]       = now

    if not baseline:
        return

    fired = False

    # 2) Channel mismatch
    ch      = extract_channel(pkt)
    exp_ch  = baseline.get("channel")
    key     = "chan_mismatch"
    last    = state["last_alert_time"]

    if ch is not None and exp_ch is not None and ch != exp_ch:
        if not state["alert_states"][key] and (now - last) > cooldown:
            generate_alert(
                bssid, ssid, ch,
                f"Channel Mismatch (Expected {exp_ch})",
                extract_rssi(pkt)
            )
            state["alert_states"][key] = True
            fired                       = True
    else:
        state["alert_states"][key] = False

    # 3) RSSI spread
    rssi = extract_rssi(pkt)
    if rssi is not None:
        lst = state["recent_rssi"]
        lst.append(rssi)
        window_size = cfg.get("rssi_window_size", RSSI_WINDOW_DEFAULT)
        lst = lst[-window_size:]
        state["recent_rssi"] = lst

        if len(lst) >= 5:
            stdev = statistics.stdev(lst)
            rng   = max(lst) - min(lst)
            key   = "rssi_spread"
            last  = state["last_alert_time"]

            if (stdev > thresh_stdev) or (rng > thresh_range):
                if not state["alert_states"][key] and (now - last) > cooldown:
                    generate_alert(
                        bssid, ssid, ch,
                        f"RSSI Spread Anomaly (StDev:{stdev:.1f} Rng:{rng:.0f}dB)",
                        rssi
                    )
                    state["alert_states"][key] = True
                    fired                       = True
            else:
                state["alert_states"][key] = False

    # 4) Absolute‐RSSI anomaly
    if rssi is not None and baseline.get("avg_rssi") is not None:
        diff = abs(rssi - baseline["avg_rssi"])
        key  = "rssi_abs"
        last = state["last_alert_time"]

        if diff > abs_thresh:
            if not state["alert_states"][key] and (now - last) > cooldown:
                generate_alert(
                    bssid, ssid, ch,
                    f"RSSI Δ > {abs_thresh} dB",
                    rssi
                )
                state["alert_states"][key] = True
                fired                       = True
        else:
            state["alert_states"][key] = False

    # --- Beacon-Rate Anomaly ---
    check_beacon_rate(state, bssid, ssid, ch, now, rssi, baseline, cfg)

    # 6) Auth/Cipher mismatch
    auth_type, cipher = parse_auth(pkt)
    exp_auth = baseline.get("auth_type")
    exp_ciph = baseline.get("cipher")
    key      = "auth_mismatch"
    last     = state["last_alert_time"]

    if (auth_type != exp_auth) or (cipher != exp_ciph):
        if not state["alert_states"][key] and (now - last) > cooldown:
            reason = (
                f"Auth Mismatch (Got {auth_type}/{cipher}, "
                f"Exp {exp_auth}/{exp_ciph})"
            )
            generate_alert(bssid, ssid, ch, reason, rssi)
            state["alert_states"][key] = True
            fired                       = True
    else:
        state["alert_states"][key] = False

    # 7) If anything fired, update last_alert_time
    if fired:
        state["last_alert_time"] = now



def run_monitoring(iface, config, profiles, known):
    """
    Kick off channel‑hopping thread and Scapy sniff loop.
    """
    if not SCAPY_AVAILABLE:
        print("Error: Scapy not available.")
        return

    global baseline_profiles_global
    global known_bssids_per_ssid_global
    global monitor_config_global

    baseline_profiles_global      = profiles
    known_bssids_per_ssid_global  = known
    monitor_config_global         = config.get("monitoring", {})

    channels = config["general"].get("channels_to_scan", [1, 6, 11])
    dwell    = monitor_config_global.get("scan_dwell_seconds", 2)

    stop_evt = threading.Event()
    hopper   = threading.Thread(
        target=channel_hopper,
        args=(iface, stop_evt, channels, dwell),
        daemon=True
    )
    hopper.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    scapy.sniff(
        iface=iface,
        prn=scapy_monitor_handler,
        store=False,
        stop_filter=lambda pkt: stop_evt.is_set()
    )

    stop_evt.set()
    hopper.join()

    if flagged_aps:
        print("\n--- Final Flagged APs ---")
        for b, d in flagged_aps.items():
            print(f"  {b} SSID:{d['ssid']} CH:{d['channel']} Reason:{d['reason']}")
        print("-------------------------")

    print("Monitoring stopped.")
