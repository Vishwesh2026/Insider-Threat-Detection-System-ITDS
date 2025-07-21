import requests
import time
import win32evtlog
from common import base_log
from malicious_ip_monitor import get_host_ip
from datetime import datetime
import time

SERVER_URL = "http://localhost:5000/agent"

def monitor_failed_logins():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    seen = set()

    while True:
        events = win32evtlog.ReadEventLog(win32evtlog.OpenEventLog(server, log_type), flags, 0)
        for event in events:
            if event.EventID == 4625:
                key = (event.RecordNumber, event.TimeGenerated)
                if key in seen:
                    continue
                seen.add(key)
                log = base_log("FAILED_LOGIN")
                log.update({
                    "EventTime":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "EventID": event.EventID,
                    "SourceName": event.SourceName,
                    "SourceAddress":get_host_ip(),
                    "AccessOutcome":"success",
                    # "DestinationIp":"N/A",
                    "ConnectionStatus":"notSuccessful",
                    "AccessOutcome":"Failed",
                    "Message": event.StringInserts[0] if event.StringInserts else "Unknown"
                })
                try:
                    res = requests.post(SERVER_URL, json=log)
                    print("[Login Monitor] Sent:", res.status_code)
                except Exception as e:
                    print("[Login Monitor] Error:", e)
        time.sleep(2)

if __name__ == "__main__":
    monitor_failed_logins()
