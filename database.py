import sqlite3
from datetime import datetime
import os
import re

DB_FOLDER = "databases"
DB_NAME = "" 

def setup_new_database_file():
    global DB_NAME
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)
        
    max_num = 0
    pattern = re.compile(r"^db_(\d+)_.*\.db$")
    
    for filename in os.listdir(DB_FOLDER):
        match = pattern.match(filename)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
                
    next_num = max_num + 1
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"db_{next_num}_{current_time}.db"
    DB_NAME = os.path.join(DB_FOLDER, filename)
    print(f"\n[*] Active Session Database: {DB_NAME}\n")

setup_new_database_file()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # ADDED: app_data column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            alert_type TEXT,
            app_data TEXT 
        )
    ''')
    conn.commit()
    conn.close()

# ADDED: app_data to arguments and SQL execution
def insert_log(src_ip, dst_ip, protocol, length, alert_type, app_data):
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute("INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, length, alert_type, app_data) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                       (timestamp, src_ip, dst_ip, protocol, length, alert_type, app_data))
        conn.commit()
        conn.close()
    except Exception as e:
        pass 

def get_all_logs():
    if not os.path.exists(DB_NAME):
        return []
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # ADDED: Fetching app_data
    cursor.execute("SELECT id, timestamp, src_ip, dst_ip, protocol, length, alert_type, app_data FROM logs ORDER BY id DESC LIMIT 500")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_ip_context(ip_address):
    if not os.path.exists(DB_NAME):
        return []
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # ADDED: Fetching app_data
    cursor.execute('''
        SELECT id, timestamp, src_ip, dst_ip, protocol, length, alert_type, app_data 
        FROM logs 
        WHERE src_ip = ? OR dst_ip = ? 
        ORDER BY id DESC LIMIT 500
    ''', (ip_address, ip_address))
    rows = cursor.fetchall()
    conn.close()
    return rows