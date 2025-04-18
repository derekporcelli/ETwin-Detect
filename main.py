# main.py
# Main script to orchestrate the Evil Twin Detector

import argparse
import os
import sys
import time
import logging
import atexit
from scapy.all import sniff, RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, \
                      Dot11AssoReq, Dot11AssoResp, Dot11Elt

# Import custom modules (assuming they are in the same directory or python path)
import monitoring
import feature_extraction
import profiling
import anomaly_detection
import alerting
# import counter # Optional for Phase 4

# --- Configuration ---
DEFAULT_DB_PATH = 'trusted_aps.db'
# Add other configurations like thresholds, learning duration etc.

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Global Variables ---
monitor = None
profiler = None
detector = None
alerter = None
# counter_module = None # Optional

# --- Packet Processing Callback ---
def packet_handler(packet):
    """
    Callback function for Scapy's sniff(). Processes captured 802.11 frames.
    """
    global detector, alerter # Add others if needed

    if not detector or not alerter:
        logging.warning("Core components not initialized yet.")
        return

    # Phase 1 & 2: Beacon and Probe Response Processing
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        features = feature_extraction.extract_beacon_probe_response_features(packet)
        if features:
            anomaly = detector.check_beacon_probe_response(features)
            if anomaly:
                alerter.generate_alert(anomaly['type'], anomaly['details'])
            # Update last seen timestamp for trusted APs
            if features.get('bssid') and not anomaly:
                 profiler.update_last_observed(features['bssid'])


    # Phase 3: Association Frame Processing
    elif packet.haslayer(Dot11AssoReq):
        features = feature_extraction.extract_association_request_features(packet)
        if features:
            detector.check_association_request(features)

    elif packet.haslayer(Dot11AssoResp):
        features = feature_extraction.extract_association_response_features(packet)
        if features:
            anomaly = detector.check_association_response(features)
            if anomaly:
                alerter.generate_alert(anomaly['type'], anomaly['details'])

    # Add processing for other frame types if needed

# --- Cleanup Function ---
def cleanup():
    """
    Function to be called on script exit to clean up resources.
    """
    global monitor, profiler
    logging.info("Cleaning up...")
    if monitor:
        monitor.set_managed_mode()
        logging.info(f"Interface {monitor.interface_name} set back to managed mode.")
    if profiler:
        profiler.close()
        logging.info("Database connection closed.")
    logging.info("Exiting Evil Twin Detector.")

# --- Main Execution ---
if __name__ == "__main__":
    # Check for root privileges (essential for monitor mode and raw sockets)
    if os.geteuid() != 0:
        logging.error("This script requires root privileges to set monitor mode and capture packets.")
        sys.exit(1)

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Evil Twin Access Point Detector")
    parser.add_argument('-i', '--interface', required=True, help="Wireless interface name to use (must support monitor mode)")
    parser.add_argument('--db', default=DEFAULT_DB_PATH, help=f"Path to the SQLite database file (default: {DEFAULT_DB_PATH})")
    parser.add_argument('--learn', metavar='BSSID', help="Activate learning mode for the specified BSSID of a trusted AP.")
    parser.add_argument('--learn-duration', type=int, default=60, help="Duration in seconds for learning mode (default: 60).")
    # Add arguments for managing trusted APs (add/remove) - Phase 1 Task 3.4
    parser.add_argument('--add-ap', nargs=2, metavar=('SSID', 'BSSID'), help="Manually add a trusted AP (SSID BSSID).")
    parser.add_argument('--remove-ap', metavar='BSSID', help="Remove a trusted AP by BSSID.")
    # Add argument for deauthentication (Phase 4)
    parser.add_argument('--enable-deauth', action='store_true', help="Enable deauthentication countermeasure (USE WITH EXTREME CAUTION).")


    args = parser.parse_args()

    # --- Initialization ---
    logging.info(f"Using interface: {args.interface}")
    logging.info(f"Using database: {args.db}")

    monitor = monitoring.Monitor(args.interface)
    profiler = profiling.Profiler(args.db)
    alerter = alerting.Alerter()
    detector = anomaly_detection.Detector(profiler) # Pass profiler to detector
    # if args.enable_deauth:
        # counter_module = counter.Counter(args.interface) # Optional
        # detector.set_counter_module(counter_module) # Need method in Detector to link them
        # logging.warning("Deauthentication enabled. This can disrupt networks.")


    # Register cleanup function
    atexit.register(cleanup)

    # --- Handle Management Actions ---
    if args.add_ap:
        ssid_to_add, bssid_to_add = args.add_ap
        if profiler.add_trusted_ap(ssid_to_add, bssid_to_add.lower()): # Store BSSID consistently
             logging.info(f"Added/Updated trusted AP: SSID='{ssid_to_add}', BSSID='{bssid_to_add.lower()}'")
        else:
             logging.error(f"Failed to add trusted AP: SSID='{ssid_to_add}', BSSID='{bssid_to_add.lower()}'")
        sys.exit(0) # Exit after management action

    if args.remove_ap:
        bssid_to_remove = args.remove_ap.lower()
        if profiler.remove_trusted_ap(bssid_to_remove):
            logging.info(f"Removed trusted AP: BSSID='{bssid_to_remove}'")
        else:
             logging.error(f"Failed to remove trusted AP or AP not found: BSSID='{bssid_to_remove}'")
        sys.exit(0) # Exit after management action


    # --- Set Interface to Monitor Mode ---
    if not monitor.set_monitor_mode():
        logging.error(f"Failed to set interface {args.interface} to monitor mode. Exiting.")
        # Cleanup might run automatically via atexit, but explicit exit is clear
        sys.exit(1)
    logging.info(f"Interface {args.interface} successfully set to monitor mode.")
    time.sleep(2) # Give interface time to settle


    # --- Learning Mode (Phase 2 Task 3.5) ---
    if args.learn:
        target_bssid = args.learn.lower()
        logging.info(f"Starting learning mode for BSSID {target_bssid} for {args.learn_duration} seconds...")
        # Need a dedicated function/method for learning
        learned_data = profiling.perform_learning(monitor.interface_name, target_bssid, args.learn_duration)
        if learned_data:
            logging.info(f"Learning complete for {target_bssid}.")
            logging.info(f"  Learned Channels: {learned_data['channels']}")
            logging.info(f"  Baseline RSSI Avg: {learned_data['rssi_avg']:.2f} dBm")
            logging.info(f"  Baseline RSSI StdDev: {learned_data['rssi_stddev']:.2f} dBm")
            # Update the database profile
            if profiler.update_trusted_ap_baseline(target_bssid,
                                                 learned_data['channels'],
                                                 learned_data['rssi_avg'],
                                                 learned_data['rssi_stddev']):
                logging.info(f"Successfully updated profile for {target_bssid} in the database.")
            else:
                logging.error(f"Failed to update profile for {target_bssid}. Ensure it exists (add it first if needed).")
        else:
            logging.warning(f"Learning mode did not capture sufficient data for BSSID {target_bssid}.")
        # Exit after learning mode - alternatively, could proceed to monitoring
        sys.exit(0)


    # --- Start Passive Scanning (Phase 1 Task 1.2) ---
    logging.info("Starting passive scan for Evil Twin APs...")
    try:
        # filter="type mgt subtype beacon or type mgt subtype probe-resp or type mgt subtype assoc-req or type mgt subtype assoc-resp" # More specific filter
        monitor.start_sniffing(packet_handler) # Blocks here until stopped
    except KeyboardInterrupt:
        logging.info("Scan stopped by user.")
    except Exception as e:
        logging.error(f"An error occurred during sniffing: {e}", exc_info=True)
    finally:
        # Cleanup is handled by atexit, but could be called explicitly here too
        pass