import socket
from datetime import datetime

def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def base_log(event_type):
    return {
        "event_type": event_type,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "SourceAddress": get_ip()
    }
