import psutil
import requests
import time
from common import base_log
from malicious_ip_monitor import get_host_ip
from datetime import datetime


SERVER_URL = "http://localhost:5000/agent"  

def collect_usb_data():
    for part in psutil.disk_partitions():
        if 'removable' in part.opts or 'media' in part.device.lower():
            log = base_log("USB_INSERT")
            log.update({
                "EventTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "EventID": "6416",
                "SerialNumber": "unknown",
                "ConnectionStatus": part.mountpoint,
                "SourceName":"USB Monitor",
                "SourceAddress":get_host_ip(),
                "AccessOutcome": "connected",
                "Message":"USB insertion",
                "even_type":"usb_insertion",
                "DestinationIp":"N/A"
            })
            return log
    return None

def main():
    already_sent = False
    while True:
        usb_data = collect_usb_data()
        if usb_data and not already_sent:
            try:
                res = requests.post(SERVER_URL, json=usb_data)
                print("[USB Monitor] Sent:", res.status_code)
                already_sent = True
            except Exception as e:
                print("[USB Monitor] Error:", e)
        elif not usb_data:
            already_sent = False
        # time.sleep(2)

if __name__ == "__main__":
    main()
