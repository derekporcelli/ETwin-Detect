import sqlite3

DB_NAME = "network_profiles.db"

def create_connection():
    return sqlite3.connect(DB_NAME)

def create_whitelist_table():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            ssid VARCHAR(300) NOT NULL,
            bssid VARCHAR(300) NOT NULL PRIMARY KEY,
            channel INTEGER,
            signal_strength INTEGER,
            user_count INTEGER
            authentication VARCHAR(300) 
            beacon_time DATETIME NOT NULL
        );
    ''')

    conn.commit()
    conn.close()
    print("[+] Table 'whitelist' created (or already exists).")


def create_blacklist_table():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            ssid VARCHAR(300) NOT NULL,
            bssid VARCHAR(300) NOT NULL PRIMARY KEY,
            channel INTEGER 
        );
    ''')

    conn.commit()
    conn.close()
    print("[+] Table 'blacklist' created (or already exists).")

def insert_aps(ssid, bssid, channel, signal_strength, user_count, authentication, beacon_time):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
            INSERT OR REPLACE INTO whitelist (
                ssid, bssid, channel, signal_strength, user_count, authentication, beacon_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        ''', (ssid, bssid, channel, signal_strength, user_count, authentication, beacon_time))

    conn.commit()
    conn.close()
    print("[+] AP Object added to 'whitelist' table.")

def insert_evil(ssid, bssid, channel):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute('''
                INSERT OR REPLACE INTO blacklist (
                    ssid, bssid, channel
                ) VALUES (?, ?, ?);
            ''', (ssid, bssid, channel))

    conn.commit()
    conn.close()
    print("[+] AP Object added to 'blacklist' table.")