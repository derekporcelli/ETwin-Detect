import subprocess
from scapy import sniff

class Monitor:
    def __init__(self, interface_name):
        interface_name = interface_name
        self.original_mode = self._get_current_mode()
    
    def get_current_mode(self):
        result = subprocess.run(['iwconfig', self.interface_name], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "Mode" in line:
                pass

