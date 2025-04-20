#!/usr/bin/env python3

import argparse
import json
import os
import signal
import shutil
import sqlite3
import subprocess
import sys
import time
import glob
import statistics
import datetime
from collections import defaultdict

import pandas as pd
import monitor_logic

# --- Defaults & Config Loader ---
CONFIG_DEFAULTS = {
    "general": {
        "interface": "wlan0",
        "db_name": "ap_profiles_airodump.db",
        "channels_to_scan": list(range(1, 12)),
        "temp_dir": "/tmp/airodump_profiling"
    },
    "profiling": {
        "dwell_time_ms": 5000,
        "scan_cycles": 1,
        "target_ssids": []
    },
    "monitoring": {
        "target_ssids": [],
        "scan_dwell_seconds": 2,
        "rssi_threshold_stdev": 3.0,
        "rssi_threshold_dbm_abs": 20,
        "rssi_spread_stdev_threshold": 10.0,
        "rssi_spread_range_threshold": 25.0,
        "beacon_rate_threshold_percent": 50.0,
        "alert_cooldown_seconds": 60
    }
}

def load_config(path):
    try:
        user_cfg = json.load(open(path))
    except FileNotFoundError:
        print(f"Config '{path}' not found."); sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Config parse error: {e}"); sys.exit(1)

    cfg = CONFIG_DEFAULTS.copy()
    for section, vals in user_cfg.items():
        if section in cfg and isinstance(cfg[section], dict):
            cfg[section].update(vals)
        else:
            cfg[section] = vals

    prof_ssids = cfg['profiling']['target_ssids']
    chans = cfg['general']['channels_to_scan']
    if not prof_ssids or not chans or cfg['profiling']['dwell_time_ms'] <= 0 or cfg['profiling']['scan_cycles'] <= 0:
        print("Invalid config values."); sys.exit(1)

    return cfg

# --- Monitor Mode ---
def set_monitor_mode(iface, enable):
    # ensure airmon-ng exists
    if subprocess.run(['which','airmon-ng'], capture_output=True).returncode:
        print("airmon-ng not found."); return None

    action = "start" if enable else "stop"
    subprocess.run(['airmon-ng','check','kill'], capture_output=True)
    subprocess.run(['airmon-ng', action, iface], capture_output=True)
    return (iface + "mon") if enable else iface

# --- DB Ops ---
def init_db():
    db = config['general']['db_name']
    with sqlite3.connect(db) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                ssid TEXT,
                bssid TEXT PRIMARY KEY,
                channel INTEGER,
                avg_rssi REAL,
                stddev_rssi REAL,
                privacy_raw TEXT,
                cipher_raw TEXT,
                authentication_raw TEXT,
                avg_beacon_rate REAL,
                profiled_time TEXT
            );
        """)

def add_to_whitelist(d):
    db = config['general']['db_name']
    with sqlite3.connect(db) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO whitelist
            (ssid,bssid,channel,avg_rssi,stddev_rssi,privacy_raw,
             cipher_raw,authentication_raw,avg_beacon_rate,profiled_time)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            d['ssid'], d['bssid'].lower(), d['channel'],
            d['avg_rssi'], d['stddev_rssi'],
            d['privacy_raw'], d['cipher_raw'], d['authentication_raw'],
            d['avg_beacon_rate'], d['profiled_time']
        ))

def load_baseline(ssids):
    db = config['general']['db_name']
    ph = ','.join('?'*len(ssids))
    q = f"SELECT ssid,bssid,channel,avg_rssi,stddev_rssi,privacy_raw,cipher_raw,authentication_raw,avg_beacon_rate FROM whitelist WHERE ssid IN ({ph})"
    rows = sqlite3.connect(db).cursor().execute(q, ssids).fetchall()
    if not rows:
        print("No baseline for", ssids)
        return None, None

    bp, kb = {}, defaultdict(set)
    for ssid,bssid,chan,avg,sd,pr,cr,ar,abr in rows:
        auth_type, cipher = parse_auth_details({pr},{cr},{ar})
        bp[bssid.lower()] = {
            'ssid': ssid, 'channel': chan,
            'avg_rssi': avg, 'stddev_rssi': sd,
            'auth_type': auth_type, 'cipher': cipher,
            'avg_beacon_rate': abr
        }
        kb[ssid].add(bssid.lower())

    return bp, kb

# Use existing parse_auth_details imported above
from __main__ import parse_auth_details

def parse_airodump_csv(path):
    lines = open(path, encoding='utf-8', errors='ignore').read().splitlines()
    aps, hdr = [], []
    in_ap = False
    for ln in lines:
        if ln.startswith("BSSID,"):
            in_ap = True
            hdr = [h.strip().replace('# beacons','#Beacons').replace(' PWR','Power')
                   .replace('channel','CH') for h in ln.split(',')]
            continue
        if ln.startswith("Station MAC,") or not ln:
            break
        if in_ap:
            vals = [v.strip() for v in ln.split(',', len(hdr)-1)]
            if len(vals)==len(hdr):
                aps.append(dict(zip(hdr, vals)))
    df = pd.DataFrame(aps)
    for c in ['Power','#Beacons','CH']:
        if c in df: df[c]=pd.to_numeric(df[c],errors='coerce')
    if 'ESSID' in df: df['ESSID']=df['ESSID'].str.strip()
    return df

def run_profiling(iface):
    print("Profiling on", iface)
    td, cycles = config['profiling']['dwell_time_ms']/1000, config['profiling']['scan_cycles']
    chans = config['general']['channels_to_scan']
    duration = max(10, len(chans)*td*cycles) + 2
    prefix = os.path.join(config['general']['temp_dir'], "scan")
    shutil.rmtree(config['general']['temp_dir'], ignore_errors=True)
    os.makedirs(config['general']['temp_dir'], exist_ok=True)

    cmd = [
        'airodump-ng','--write',prefix,
        '-c','.join(map(str,chans))',
        '-f',str(config['profiling']['dwell_time_ms']),
        '--write-interval','1','--output-format','csv',iface
    ]
    proc = subprocess.Popen(cmd, preexec_fn=os.setsid)
    end = time.time()+duration
    try:
        while time.time()<end:
            if proc.poll() is not None:
                print("airodump exited early"); break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)

    # process CSV
    csvs = glob.glob(f"{prefix}-*.csv")
    if not csvs:
        print("No CSV found"); return
    df = parse_airodump_csv(sorted(csvs)[0])
    if df.empty:
        print("No APs"); return

    df = df[df['ESSID'].isin(config['profiling']['target_ssids'])]
    if df.empty:
        print("No target SSIDs"); return

    agg = defaultdict(lambda:{
        'ssid':None,'rssi':[],'ch_rssi':defaultdict(list),
        'beacons':0,'priv':set(),'cip':set(),'auth':set()
    })
    for _,r in df.iterrows():
        b=r['BSSID']; s=r['ESSID']; p=r['Power']; bcn=r['#Beacons']
        agg[b]['ssid']=s
        if pd.notna(p): agg[b]['rssi'].append(p); agg[b]['ch_rssi'][r['CH']].append(p)
        agg[b]['beacons']+=int(bcn or 0)
        agg[b]['priv'].add(r.get('Privacy',''))
        agg[b]['cip'].add(r.get('Cipher',''))
        agg[b]['auth'].add(r.get('Authentication',''))

    now = datetime.datetime.now().isoformat()
    for b,data in agg.items():
        if not data['ssid']:
            continue
        vals = data['rssi']
        avg = round(statistics.mean(vals),2) if vals else None
        sd = round(statistics.stdev(vals),2) if len(vals)>1 else 0
        best_ch = max(data['ch_rssi'], key=lambda c: statistics.mean(data['ch_rssi'][c]), default=None)
        rate = round(data['beacons']/duration,2) if duration>0 else 0
        pr = sorted(data['priv'])[0] if data['priv'] else None
        cr = sorted(data['cip'])[0] if data['cip'] else None
        ar = sorted(data['auth'])[0] if data['auth'] else None

        profile = {
            'ssid': data['ssid'], 'bssid': b, 'channel': best_ch,
            'avg_rssi': avg, 'stddev_rssi': sd,
            'privacy_raw': pr, 'cipher_raw': cr, 'authentication_raw': ar,
            'avg_beacon_rate': rate, 'profiled_time': now
        }
        print("Saving", profile)
        add_to_whitelist(profile)

    shutil.rmtree(config['general']['temp_dir'], ignore_errors=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('-c','--config',default='config.json')
    p.add_argument('-f','--profile',action='store_true')
    p.add_argument('-m','--monitor',action='store_true')
    args = p.parse_args()

    config = load_config(args.config)

    if args.profile and args.monitor:
        print("Choose one mode"); sys.exit(1)
    if not (args.profile or args.monitor):
        p.print_help(); sys.exit(1)
    if os.geteuid()!=0:
        print("Root needed"); sys.exit(1)

    init_db()

    iface = config['general']['interface']
    mon_iface = set_monitor_mode(iface, True)
    if not mon_iface:
        print("Monitor mode failed"); sys.exit(1)

    try:
        if args.profile:
            run_profiling(mon_iface)
        else:
            b,p = load_baseline(config['monitoring']['target_ssids'])
            if not b:
                print("No baseline"); sys.exit(1)
            monitor_logic.run_monitoring(mon_iface, config, b, p)
    finally:
        set_monitor_mode(mon_iface, False)
        print("Done")
