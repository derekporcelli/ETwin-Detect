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
import scapy.all as scapy
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Elt,
    RadioTap,
)

# --- Global State ---
ap_monitor_state = collections.defaultdict(
    lambda: {
        "recent_rssi": [],
        "channel_state": collections.defaultdict(lambda: {
            "beacon_ts": [],
            "last_beacon_rate_check": 0,
            "airtime": 0.0,
            "last_enter_ts": None
        }),
        "last_auth_type": None,
        "last_cipher": None,
        "alert_states": collections.defaultdict(bool),
        "last_alert_time": 0,
    }
)
flagged_aps = {}
baseline_profiles_global = {}
known_bssids_per_ssid_global = {}
monitor_config_global = {}

# --- Default Thresholds (used if config missing) ---
RSSI_STDEV_THRESH_DEFAULT = 10.0
RSSI_RANGE_THRESH_DEFAULT = 25.0
RSSI_ABS_THRESH_DEFAULT = 20.0
BEACON_PCT_THRESH_DEFAULT = 50.0
ALERT_COOLDOWN_DEFAULT = 5
BEACON_WINDOW_SECONDS_DEFAULT = 20
RSSI_WINDOW_DEFAULT = 20


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
    Parse RSN (WPA2+) and WPA (legacy) elements to extract true cipher/auth types.
    Returns (auth_type, cipher) as strings like 'WPA2-PSK', 'CCMP'.
    """
    privacy = set()
    cipher = set()
    auth = set()

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        # WPA2/3: RSN Information Element
        if elt.ID == 48 and len(elt.info) >= 18:
            privacy.add("WPA2")
            data = elt.info

            group_cipher = data[2:6]
            pairwise_cipher = data[8:12]
            akm = data[14:18]

            # Cipher suite (group)
            if group_cipher == b"\x00\x0f\xac\x04":
                cipher.add("CCMP")
            elif group_cipher == b"\x00\x0f\xac\x02":
                cipher.add("TKIP")
            elif group_cipher == b"\x00\x0f\xac\x08":
                cipher.add("GCMP-256")

            # AKM suite (auth method)
            if akm == b"\x00\x0f\xac\x02":
                auth.add("PSK")
            elif akm == b"\x00\x0f\xac\x01":
                auth.add("EAP")
            elif akm == b"\x00\x0f\xac\x08":
                auth.add("SAE")

        # WPA1: Vendor-specific (Microsoft OUI)
        elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01") and len(elt.info) >= 16:
            privacy.add("WPA")
            data = elt.info

            cipher_suite = data[8:12]
            akm = data[12:16]

            if cipher_suite == b"\x00\x50\xf2\x02":
                cipher.add("TKIP")
            elif cipher_suite == b"\x00\x50\xf2\x04":
                cipher.add("CCMP")

            if akm == b"\x00\x50\xf2\x01":
                auth.add("PSK")
            elif akm == b"\x00\x50\xf2\x02":
                auth.add("EAP")

        elt = elt.payload.getlayer(Dot11Elt)

    # Fallback for WEP/Open
    cap = None
    if pkt.haslayer(Dot11Beacon):
        cap = pkt[Dot11Beacon].cap
    elif pkt.haslayer(Dot11ProbeResp):
        cap = pkt[Dot11ProbeResp].cap

    if cap and getattr(cap, "privacy", False) and not privacy:
        privacy.add("WEP")
        cipher.add("WEP")
        auth.add("WEP")
    elif not privacy:
        privacy.add("OPN")
        cipher.add("None")
        auth.add("None")

    return parse_auth_details(privacy, cipher, auth)



def channel_hopper(iface, stop_evt, channels, dwell):
    """
    Hop through the given channels and update airtime tracking for each BSSID.
    """
    idx = 0
    num_channels = len(channels)

    current_ch = channels[0]
    for bssid in ap_monitor_state:
        ap_monitor_state[bssid]["channel_state"][current_ch]["last_enter_ts"] = time.time()

    while not stop_evt.is_set():
        next_ch = channels[idx % num_channels]

        now = time.time()

        for bssid in ap_monitor_state:
            ch_state = ap_monitor_state[bssid]["channel_state"][current_ch]
            enter_ts = ch_state.get("last_enter_ts")
            if enter_ts:
                ch_state["airtime"] += now - enter_ts

        subprocess.run(["iwconfig", iface, "channel", str(next_ch)])

        for bssid in ap_monitor_state:
            ap_monitor_state[bssid]["channel_state"][next_ch]["last_enter_ts"] = time.time()

        current_ch = next_ch
        time.sleep(dwell)
        idx += 1



# Beacon Rate check helper function
def check_beacon_rate(state, bssid, ssid, ch, now, rssi, baseline, cfg):
    """
    Check for beacon-rate anomalies every N seconds using a per-channel window.
    """
    window      = cfg.get("beacon_time_window", BEACON_WINDOW_SECONDS_DEFAULT)
    beacon_pct  = cfg.get("beacon_rate_threshold_percent", BEACON_PCT_THRESH_DEFAULT)
    cooldown    = cfg.get("alert_cooldown_seconds", ALERT_COOLDOWN_DEFAULT)
    last_alert  = state.get("last_alert_time", 0)
    key         = "beacon_rate"

    # Access per-channel buffer & timestamp
    ch_state = state["channel_state"][ch]
    ch_buf   = ch_state["beacon_ts"]
    last_rate = ch_state["last_beacon_rate_check"]

    # Add current timestamp and trim old ones
    ch_buf.append(now)

    # Listen time = how long we've seen beacons on this channel
    listen_time = ch_state["airtime"]

    if listen_time < window or (now - last_rate) < window:
        return

    base_rate = baseline.get("avg_beacon_rate")
    if not base_rate or base_rate <= 0:
        return

    current_rate = (len(ch_buf) - 1) / listen_time if listen_time > 0 else 0
    pct_diff = abs(current_rate - base_rate) / base_rate * 100

    if (now - last_alert) > cooldown:
        state["alert_states"][key] = False

    
    print(f"Current rate in channel {ch}: {current_rate} === Debug") # For Debug

    if pct_diff > beacon_pct and not state["alert_states"][key] and current_rate != 0.0:
        generate_alert(
            bssid,
            ssid,
            ch,
            f"Beacon-Rate Δ {pct_diff:.0f}% > {beacon_pct}%; Current rate: {current_rate:.2f}",
            rssi,
        )
        state["alert_states"][key] = True
        state["last_alert_time"] = now
    else:
        state["alert_states"][key] = False

    # Always update last per-channel rate check
    ch_state["last_beacon_rate_check"] = now
    ch_state["beacon_ts"].clear()
    ch_state["airtime"] = 0.0




def scapy_monitor_handler(pkt):
    """
    Packet handler for Scapy sniff() — performs all anomaly checks
    using thresholds from monitor_config_global, including batched
    beacon‑rate checks every N seconds.
    """

    cfg = monitor_config_global
    targets = cfg.get("target_ssids", [])
    thresh_stdev = cfg.get("rssi_spread_stdev_threshold", RSSI_STDEV_THRESH_DEFAULT)
    thresh_range = cfg.get("rssi_spread_range_threshold", RSSI_RANGE_THRESH_DEFAULT)
    abs_thresh = cfg.get("rssi_threshold_dbm_abs", RSSI_ABS_THRESH_DEFAULT)
    cooldown = cfg.get("alert_cooldown_seconds", ALERT_COOLDOWN_DEFAULT)

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
    now = pkt.time

    # SSID filter
    ssid = extract_ssid(pkt)
    if ssid not in targets:
        return

    state = ap_monitor_state[bssid]
    baseline = baseline_profiles_global.get(bssid)
    known = known_bssids_per_ssid_global.get(ssid, set())

    # 1) Unknown‐BSSID check
    if bssid not in known:
        last = state["last_alert_time"]
        key = "new_bssid"
        if (now - last) > cooldown:
            state["alert_states"][key] = False
        if not state["alert_states"][key]:
            generate_alert(
                bssid,
                ssid,
                extract_channel(pkt),
                "Different BSSID (Potential Evil Twin)",
                extract_rssi(pkt),
            )
            state["alert_states"][key] = True
            state["last_alert_time"] = now

    if not baseline:
        return

    fired = False

    # 2) Channel mismatch
    ch = extract_channel(pkt)
    exp_ch = baseline.get("channel")
    key = "chan_mismatch"
    last = state["last_alert_time"]

    if ch is not None and exp_ch is not None and ch != exp_ch:
        if not state["alert_states"][key] and (now - last) > cooldown:
            generate_alert(
                bssid,
                ssid,
                ch,
                f"Channel Mismatch (Expected {exp_ch})",
                extract_rssi(pkt),
            )
            state["alert_states"][key] = True
            fired = True
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
            rng = max(lst) - min(lst)
            key = "rssi_spread"
            last = state["last_alert_time"]

            if (stdev > thresh_stdev) or (rng > thresh_range):
                if not state["alert_states"][key] and (now - last) > cooldown:
                    generate_alert(
                        bssid,
                        ssid,
                        ch,
                        f"RSSI Spread Anomaly (StDev:{stdev:.1f} Rng:{rng:.0f}dB)",
                        rssi,
                    )
                    state["alert_states"][key] = True
                    fired = True
            else:
                state["alert_states"][key] = False

    # 4) Absolute‐RSSI anomaly
    if rssi is not None and baseline.get("avg_rssi") is not None:
        diff = abs(rssi - baseline["avg_rssi"])
        key = "rssi_abs"
        last = state["last_alert_time"]

        if diff > abs_thresh:
            if not state["alert_states"][key] and (now - last) > cooldown:
                generate_alert(bssid, ssid, ch, f"RSSI Δ > {abs_thresh} dB", rssi)
                state["alert_states"][key] = True
                fired = True
        else:
            state["alert_states"][key] = False

    # --- Beacon-Rate Anomaly ---
    check_beacon_rate(state, bssid, ssid, ch, now, rssi, baseline, cfg)

    # 6) Auth/Cipher mismatch
    auth_type, cipher = parse_auth(pkt)
    exp_auth = baseline.get("auth_type")
    exp_ciph = baseline.get("cipher")
    key = "auth_mismatch"
    last = state["last_alert_time"]

    if (auth_type != exp_auth) or (cipher != exp_ciph):
        if not state["alert_states"][key] and (now - last) > cooldown:
            reason = (
                f"Auth Mismatch (Got {auth_type}/{cipher}, "
                f"Exp {exp_auth}/{exp_ciph})"
            )
            generate_alert(bssid, ssid, ch, reason, rssi)
            state["alert_states"][key] = True
            fired = True
    else:
        state["alert_states"][key] = False

    if fired:
        state["last_alert_time"] = now


def run_monitoring(iface, config, profiles, known):
    """
    Kick off channel‑hopping thread and Scapy sniff loop.
    """

    global baseline_profiles_global
    global known_bssids_per_ssid_global
    global monitor_config_global

    baseline_profiles_global = profiles
    known_bssids_per_ssid_global = known
    monitor_config_global = config.get("monitoring", {})

    channels = config["general"].get("channels_to_scan", [1, 6, 11])
    dwell = monitor_config_global.get("scan_dwell_seconds", 2)

    stop_evt = threading.Event()
    hopper = threading.Thread(
        target=channel_hopper, args=(iface, stop_evt, channels, dwell), daemon=True
    )
    hopper.start()

    print("Monitoring started. Press Ctrl+C to stop.")
    scapy.sniff(
        iface=iface,
        prn=scapy_monitor_handler,
        store=False,
        stop_filter=lambda pkt: stop_evt.is_set(),
    )

    stop_evt.set()
    hopper.join()

    if flagged_aps:
        print("\n--- Final Flagged APs ---")
        for b, d in flagged_aps.items():
            print(f"  {b} SSID:{d['ssid']} CH:{d['channel']} Reason:{d['reason']}")
        print("-------------------------")

    print("Monitoring stopped.")
