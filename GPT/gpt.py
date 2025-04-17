#!/usr/bin/env python3
"""
evil_twin.py – minimal PoC that whitelists nearby APs (SSID + BSSID) and
raises an alert when an SSID reappears from an unseen BSSID.

▪︎ Requires:   scapy>=2.5.0  (pip install scapy)
▪︎ Privilege:  run as root, interface in monitor mode (e.g. wlan0mon)
"""

import argparse, json, sys, time, statistics, pathlib, logging
from collections import defaultdict

from scapy.all import (
    sniff,
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    get_if_hwaddr,
)

PROFILE_DB = "trusted_aps.json"

# ──────────────────────────────────────────────────────────────────────────────
def beacon_cb(pkt, store):
    if not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeResp):
        return
    dot11 = pkt[Dot11]
    if dot11.type != 0 or dot11.subtype not in (8, 5):  # beacon / probe‑resp
        return

    ssid = pkt.getfieldval("info").decode(errors="ignore")
    if not ssid:  # hidden SSID
        return
    bssid = dot11.addr2.lower()
    rssi  = pkt.dBm_AntSignal if pkt.dBm_AntSignal is not None else None
    chan  = pkt[Dot11Beacon].network_stats().get("channel", None)

    entry = store[ssid].setdefault(bssid, {
        "channel": chan,
        "rssi_samples": [],
        "first_seen": time.time(),
    })
    if rssi is not None:
        entry["rssi_samples"].append(rssi)

# ──────────────────────────────────────────────────────────────────────────────
def run_profile(iface: str, seconds: int):
    logging.info(f"[Profiling] capturing for {seconds} s on {iface} …")
    store = defaultdict(dict)
    sniff(iface=iface,
          prn=lambda p: beacon_cb(p, store),
          timeout=seconds,
          monitor=True)

    # summarise statistics
    summary = {}
    for ssid, bssids in store.items():
        summary[ssid] = {}
        for bssid, data in bssids.items():
            samples = data["rssi_samples"]
            summary[ssid][bssid] = {
                "channel": data["channel"],
                "rssi_mu": statistics.mean(samples) if samples else None,
                "rssi_sigma": statistics.stdev(samples) if len(samples) > 1 else None,
            }

    pathlib.Path(PROFILE_DB).write_text(json.dumps(summary, indent=2))
    logging.info(f"[Profiling] wrote {len(summary)} SSIDs to {PROFILE_DB}")

# ──────────────────────────────────────────────────────────────────────────────
def load_profiles() -> dict:
    try:
        with open(PROFILE_DB, "r") as fp:
            return json.load(fp)
    except FileNotFoundError:
        logging.error(f"No {PROFILE_DB} found. Run with --profile first.")
        sys.exit(1)

def is_clone(pkt, profiles):
    ssid = pkt.getfieldval("info").decode(errors="ignore")
    if not ssid or ssid not in profiles:
        return False
    bssid = pkt[Dot11].addr2.lower()
    return bssid not in profiles[ssid]

def alert(pkt):
    ssid  = pkt.getfieldval("info").decode(errors="ignore")
    bssid = pkt[Dot11].addr2.lower()
    rssi  = pkt.dBm_AntSignal
    chan  = pkt[Dot11Beacon].network_stats().get("channel", None)
    msg   = (f"[⚠] Possible Evil‑Twin detected!  SSID={ssid!r}  "
             f"BSSID={bssid}  CH={chan}  RSSI={rssi} dBm")
    logging.warning(msg)

# ──────────────────────────────────────────────────────────────────────────────
def run_monitor(iface: str):
    profiles = load_profiles()
    logging.info(f"[Monitor] loaded {len(profiles)} profiled SSIDs")
    sniff(iface=iface,
          prn=lambda p: alert(p) if (p.haslayer(Dot11Beacon)
                                     and is_clone(p, profiles)) else None,
          store=0, monitor=True)

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("evil_twin.log")]
    )

    ap = argparse.ArgumentParser(description="Evil‑Twin AP detector")
    ap.add_argument("--iface", required=True, help="monitor‑mode interface (e.g. wlan0)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--profile", action="store_true", help="build baseline whitelist")
    mode.add_argument("--monitor", action="store_true", help="run live monitoring")
    ap.add_argument("--seconds", type=int, default=60, help="capture duration for profiling")

    args = ap.parse_args()

    if args.profile:
        run_profile(args.iface, args.seconds)
    elif args.monitor:
        run_monitor(args.iface)