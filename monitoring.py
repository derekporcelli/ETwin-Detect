import subprocess
import shutil
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import anomaly_detection

class Monitor:
    def __init__(self, interface=None, whitelist=None, anomaly_detector=None):
        # Step 1.1.1: Identify wireless interface if not provided
        self.interface = interface or self.get_wireless_interface()
        # Save original mode to revert later
        self.original_mode = self._get_current_mode()

        # Anomaly detection
        self.anomaly_detector = anomaly_detector or anomaly_detection.AnomalyDetector(self)

    @staticmethod
    def get_wireless_interface():
        """
        Detect first wireless interface via 'iw dev'.
        """
        try:
            out = subprocess.check_output(['iw', 'dev'], text=True)
            for line in out.splitlines():
                if line.strip().startswith('Interface'):
                    return line.split()[1]
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to list wireless interfaces.")
        raise RuntimeError("No wireless interface found.")

    def _get_current_mode(self):
        """
        Query current mode (Managed/Monitor) via iwconfig.
        """
        try:
            out = subprocess.check_output(['iwconfig', self.interface], text=True)
            for line in out.splitlines():
                if 'Mode:' in line:
                    return line.split('Mode:')[1].split()[0]
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Cannot get mode for interface {self.interface}.")
        return None

    def set_monitor_mode(self):
        """
        Step 1.1.2: Enable monitor mode (prefer airmon-ng, fallback to ip/iw).
        """
        try:
            if shutil.which('airmon-ng'):
                subprocess.run(['airmon-ng', 'start', self.interface], check=True)
                self.interface = self.get_wireless_interface()
            else:
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
                subprocess.run(['iw', 'dev', self.interface, 'set', 'type', 'monitor'], check=True)
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to set {self.interface} to monitor mode: {e}")

    def revert_mode(self):
        """
        Step 1.1.4: Revert back to managed mode on exit.
        """
        try:
            if shutil.which('airmon-ng'):
                subprocess.run(['airmon-ng', 'stop', self.interface], check=True)
            else:
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
                subprocess.run(['iw', 'dev', self.interface, 'set', 'type', 'managed'], check=True)
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to revert {self.interface} to managed mode: {e}")

    def set_channel(self, channel):
        """
        Step 1.1.5: Set interface to a specific channel.
        """
        try:
            if shutil.which('iw'):
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)], check=True)
            else:
                subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to set channel {channel}: {e}")

    def packet_handler(self, pkt):
        """
        Step 1.2.2 - 1.2.4: Handle management frames and compare against whitelist.
        """
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt.haslayer(Dot11Elt) else ''
            bssid = pkt[Dot11].addr2

            self.anomaly_detector.check_bssid_whitelist(ssid, bssid, pkt)


    def start_sniff(self, timeout=None):
        """
        Step 1.2.1 & 1.2.5: Begin passive sniffing (with optional channel hopping).
        """
        try:
            sniff(iface=self.interface,
                  prn=self.packet_handler,
                  store=False,
                  timeout=timeout)
        except KeyboardInterrupt:
            pass