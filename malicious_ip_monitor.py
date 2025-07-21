import time
import socket
import requests
from datetime import datetime
import psutil

def get_outgoing_dest_ips():
    connections = psutil.net_connections(kind='inet')
    dest_ips = set()
    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            dest_ips.add(conn.raddr.ip)
    return list(dest_ips)
MALICIOUS_IP_FILE = "data/malicious_ips.txt"
SERVER_URL = "http://localhost:5000/agent"

def load_malicious_ips():
    try:
        with open(MALICIOUS_IP_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print("[MaliciousIPMonitor] ⚠️ Malicious IP list not found.")
        return set()

def get_host_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def check_ip_against_blacklist(destination_ip, malicious_ips):
    return destination_ip in malicious_ips

def send_malicious_ip_log(destination_ip):
    log = {
        "EventTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "EventID": 9001,
        "SourceName": "MaliciousIPMonitor",
        "Message": f"Detected connection attempt to malicious IP: {destination_ip}",
        "SourceAddress": get_host_ip(),
        "DestinationIp": destination_ip,
        "event_type": "MALICIOUS_CONNECTION",
        "AccessOutcome": "success",
        "ConnectionStatus":"connected"
    }
    try:
        res = requests.post(SERVER_URL, json=log)
        print(f"[MaliciousIPMonitor] 🚨 Detected malicious IP: {destination_ip} | Status: {res.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[MaliciousIPMonitor] ❌ Failed to send log: {e}")

def main():
    print("[MaliciousIPMonitor] 🟢 Monitoring destination IPs...")
    malicious_ips = load_malicious_ips()

    # Example pool of destination IPs to simulate network events

    while True:
        ips_list=get_outgoing_dest_ips()
        for ip in ips_list:
            if check_ip_against_blacklist(ip, malicious_ips):
                send_malicious_ip_log(ip)
        time.sleep(1)  # Check every 10 seconds

if __name__ == "__main__":
    main()
