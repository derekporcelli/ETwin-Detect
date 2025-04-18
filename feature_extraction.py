# feature_extraction.py
# Module for extracting relevant features from 802.11 management frames

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Elt
)


def extract_beacon_probe_response_features(packet):
    """
    Extract features from beacon or probe response frames.
    Returns a dict of features or None if extraction fails.
    """
    # Determine which layer we have
    if packet.haslayer(Dot11Beacon):
        mgmt = packet[Dot11Beacon]
        frame_type = 'beacon'
    elif packet.haslayer(Dot11ProbeResp):
        mgmt = packet[Dot11ProbeResp]
        frame_type = 'probe_resp'
    else:
        return None

    # Basic 802.11 fields
    try:
        bssid = packet[Dot11].addr3
        ssid = None
        channel = None
        rates = []
        timestamp = getattr(mgmt, 'timestamp', None)
        beacon_interval = getattr(mgmt, 'beacon_interval', None)

        # Parse Tagged Parameters
        elt = mgmt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID
                ssid = elt.info.decode(errors='ignore')
            elif elt.ID == 3 and len(elt.info) >= 1:  # DS Parameter Set (Channel)
                channel = elt.info[0]
            elif elt.ID in (1, 50):  # Supported Rates / Extended Rates
                # Each byte is a rate in 0.5 Mbps increments
                for rate_byte in elt.info:
                    # mask off the highest bit
                    rates.append((rate_byte & 0x7F) * 0.5)
            elt = elt.payload.getlayer(Dot11Elt)

        features = {
            'frame_type': frame_type,
            'bssid': bssid,
            'ssid': ssid,
            'channel': channel,
            'rates': sorted(set(rates)),
            'timestamp': timestamp,
            'beacon_interval': beacon_interval
        }
        return features

    except Exception:
        return None


def extract_association_request_features(packet):
    """
    Extract features from association request frames.
    Returns a dict of features or None if extraction fails.
    """
    if not packet.haslayer(Dot11AssoReq):
        return None

    try:
        req = packet[Dot11AssoReq]
        src = packet[Dot11].addr2  # client MAC
        dst = packet[Dot11].addr1  # AP MAC
        ssid = None
        rates = []

        # Parse IEs for SSID and Supported Rates
        elt = req.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                ssid = elt.info.decode(errors='ignore')
            elif elt.ID in (1, 50):
                for rate_byte in elt.info:
                    rates.append((rate_byte & 0x7F) * 0.5)
            elt = elt.payload.getlayer(Dot11Elt)

        features = {
            'frame_type': 'assoc_req',
            'src': src,
            'dst': dst,
            'ssid': ssid,
            'rates': sorted(set(rates))
        }
        return features

    except Exception:
        return None


def extract_association_response_features(packet):
    """
    Extract features from association response frames.
    Returns a dict of features or None if extraction fails.
    """
    if not packet.haslayer(Dot11AssoResp):
        return None

    try:
        resp = packet[Dot11AssoResp]
        src = packet[Dot11].addr2  # AP MAC
        dst = packet[Dot11].addr1  # client MAC
        status = getattr(resp, 'status', None)
        capabilities = getattr(resp, 'cap', None)

        features = {
            'frame_type': 'assoc_resp',
            'src': src,
            'dst': dst,
            'status': status,
            'capabilities': capabilities
        }
        return features

    except Exception:
        return None