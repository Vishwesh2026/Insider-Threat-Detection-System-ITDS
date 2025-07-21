import multiprocessing
import usb_monitor
import malicious_ip_monitor
import failed_login_monitor

def start_all():
    p1 = multiprocessing.Process(target=usb_monitor.main)
    p2 = multiprocessing.Process(target=malicious_ip_monitor.main)
    p3 = multiprocessing.Process(target=failed_login_monitor.monitor_failed_logins)

    p1.start()
    p2.start()
    p3.start()

    p1.join()
    p2.join()
    p3.join()

if __name__ == '__main__':
    start_all()
