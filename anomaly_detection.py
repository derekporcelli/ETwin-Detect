# anomaly_detection.py

from scapy.all import Dot11Elt

class AnomalyDetector:
    def __init__(self, profiler):
        self.profiler = profiler
        self.blacklist = set()

    def get_channel_from_packet(self, pkt):
        if not pkt.haslayer(Dot11Elt):
            return None

        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3:
                return elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    def check_bssid_whitelist(self, ssid, bssid, pkt):
        trusted_ssids = self.profiler.get_trusted_ssids()
        known_bssids = self.profiler.get_known_bssids()
        channel = self.get_channel_from_packet(self, pkt)

        if ssid in trusted_ssids and bssid not in known_bssids:
            alert_msg = f"[!] SSID Spoofing Detected: SSID '{ssid}' from unknown BSSID '{bssid}'"
            print(alert_msg)

            if bssid not in self.blacklist:
                self.profiler.set_ap_status(bssid, status='RAP', reason='SSID_SPOOFING', channel=int(channel))
                self.blacklist.add(bssid)
                print(f"[+] Flagged {bssid} as RAP for SSID spoofing on Channel {channel}.")
            else:
                print(f"[-] BSSID {bssid} already flagged.")

    def analyze_ap(self, ssid, bssid):
        self.check_bssid_whitelist(ssid, bssid)
