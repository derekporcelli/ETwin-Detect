#!/usr/bin/env python3
"""
evil_twin.py – minimal proof‑of‑concept Evil‑Twin detector.

▪︎ --profile : assume the RF environment is clean, whitelist everything seen
▪︎ --monitor : compare future beacons against the whitelist, warn on clones

Run as root with the interface already in *monitor* mode.
"""

import argparse, json, sys, time, statistics, pathlib, logging
from collections import defaultdict
from scapy.all import (
    sniff,
    Dot11,             # main 802.11 header
    Dot11Beacon,       # subtype 8 (beacon frame)
    Dot11ProbeResp,    # subtype 5 (probe response)
)

PROFILE_DB = "trusted_aps.json"       # file where we persist the whitelist

# ──────────────────────────────────────────────────────────────────────────────
def beacon_cb(pkt, store: dict):
    """
    Callback for scapy during the *profile* session.
    Collects statistics about every beacon / probe‑response.
    """
    # Only process management frames type=0, subtype=beacon(8)/probe‑resp(5)
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return
    dot11 = pkt[Dot11]
    if dot11.type != 0 or dot11.subtype not in (8, 5):
        return

    # ----- extract fields we care about -----
    ssid = pkt.getfieldval("info").decode(errors="ignore")      # SSID string
    if not ssid:                 # ignore “hidden‑ssid” beacons
        return
    bssid = dot11.addr2.lower()  # transmitter MAC
    rssi  = pkt.dBm_AntSignal if pkt.dBm_AntSignal is not None else None
    chan  = pkt[Dot11Beacon].network_stats().get("channel", None)

    # ----- accumulate into the in‑memory store -----
    entry = store[ssid].setdefault(bssid, {
        "channel": chan,
        "rssi_samples": [],
        "first_seen": time.time(),
    })
    if rssi is not None:
        entry["rssi_samples"].append(rssi)


# ──────────────────────────────────────────────────────────────────────────────
def run_profile(iface: str, seconds: int):
    """
    Capture beacons for <seconds>, then write a whitelist JSON file.
    """
    logging.info(f"[Profiling] capturing for {seconds}s on {iface}")
    store = defaultdict(dict)

    sniff(iface=iface,
          prn=lambda p: beacon_cb(p, store),
          timeout=seconds,
          monitor=True)        # stop after <seconds>

    # Post‑process: compress raw samples into mean / sigma to save space
    summary = {}
    for ssid, bssids in store.items():
        summary[ssid] = {}
        for bssid, data in bssids.items():
            samples = data["rssi_samples"]
            summary[ssid][bssid] = {
                "channel": data["channel"],
                "rssi_mu": statistics.mean(samples) if samples else None,
                "rssi_sigma": (
                    statistics.stdev(samples) if len(samples) > 1 else None
                ),
            }

    pathlib.Path(PROFILE_DB).write_text(json.dumps(summary, indent=2))
    logging.info(f"[Profiling] stored {len(summary)} SSIDs → {PROFILE_DB}")


# ──────────────────────────────────────────────────────────────────────────────
def load_profiles() -> dict:
    """Read the JSON whitelist from disk, exit if it does not exist."""
    try:
        with open(PROFILE_DB, "r") as fp:
            return json.load(fp)
    except FileNotFoundError:
        logging.error(f"No {PROFILE_DB} found. Run with --profile first.")
        sys.exit(1)


def is_clone(pkt, profiles) -> bool:
    """
    Return True when a beacon’s SSID is known but its BSSID is *new*,
    i.e., the hallmark of an Evil‑Twin.
    """
    ssid = pkt.getfieldval("info").decode(errors="ignore")
    if not ssid or ssid not in profiles:
        return False
    bssid = pkt[Dot11].addr2.lower()
    return bssid not in profiles[ssid]


def alert(pkt):
    """Print and log a formatted warning about the suspicious beacon."""
    ssid  = pkt.getfieldval("info").decode(errors="ignore")
    bssid = pkt[Dot11].addr2.lower()
    rssi  = pkt.dBm_AntSignal
    chan  = pkt[Dot11Beacon].network_stats().get("channel", None)
    msg   = (f"[⚠] Possible Evil‑Twin!  SSID={ssid!r}  "
             f"BSSID={bssid}  CH={chan}  RSSI={rssi} dBm")
    logging.warning(msg)


# ──────────────────────────────────────────────────────────────────────────────
def run_monitor(iface: str):
    """Load whitelist and watch the airspace indefinitely."""
    profiles = load_profiles()
    logging.info(f"[Monitor] watching for clones of {len(profiles)} SSIDs")

    sniff(iface=iface,
          prn=lambda p: alert(p) if (
                  p.haslayer(Dot11Beacon) and is_clone(p, profiles)
              ) else None,
          store=0,
          monitor=True)     # no timeout → run forever


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # ----- basic logging to console + file -----
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("evil_twin.log")
        ]
    )

    # ----- command‑line interface -----
    ap = argparse.ArgumentParser(description="Evil‑Twin AP detector")
    ap.add_argument("--iface", required=True,
                    help="monitor‑mode interface (e.g. wlan0mon)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--profile", action="store_true",
                      help="build baseline whitelist")
    mode.add_argument("--monitor", action="store_true",
                      help="run live monitoring")
    ap.add_argument("--seconds", type=int, default=60,
                    help="capture duration for profiling")
    args = ap.parse_args()

    # ----- dispatch -----
    if args.profile:
        run_profile(args.iface, args.seconds)
    elif args.monitor:
        run_monitor(args.iface)