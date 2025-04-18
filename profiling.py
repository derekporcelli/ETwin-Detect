import subprocess
from scapy.all import sniff, Dot11
from collections import defaultdict, Counter
import time

class APProfiler:
    def __init__(self):
        self.aps = {}
        self.suspected_raps = set()
        self.running_record = []

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:
                ssid = pkt.info.decode(errors='ignore')
                bssid = pkt.addr2

                if ssid and bssid:
                    key = (ssid, bssid)
                    if key not in self.aps:
                        self.aps[key] = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'last_seen': time.time()
                        }

                    # Update last seen
                    self.aps[key]['last_seen'] = time.time()

                    # Check for duplicate SSIDs or BSSIDs
                    self.check_for_raps()

                    # Update top 30 running record
                    self.update_top_30()

    def check_for_raps(self):
        ssid_counter = Counter([ap['ssid'] for ap in self.aps.values()])
        bssid_counter = Counter([ap['bssid'] for ap in self.aps.values()])

        for ap in self.aps.values():
            if ssid_counter[ap['ssid']] > 1 or bssid_counter[ap['bssid']] > 1:
                self.suspected_raps.add((ap['ssid'], ap['bssid']))
                print(f"[!] Suspected RAP Detected: SSID={ap['ssid']} | BSSID={ap['bssid']}")
                print("[!] Pausing monitoring...")
                time.sleep(5)  # Simulate pause

    def update_top_30(self):
        # Sort APs by last_seen and keep only top 30 most recently seen
        sorted_aps = sorted(self.aps.values(), key=lambda x: x['last_seen'], reverse=True)
        self.running_record = sorted_aps[:30]

    def start_profiling(self, iface='wlan0mon'):
        print("[*] Starting AP profiling...")
        sniff(iface=iface, prn=self.packet_handler, store=0)

if __name__ == "__main__":
    profiler = APProfiler()
    profiler.start_profiling()