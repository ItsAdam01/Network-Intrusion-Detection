"""
attacker.py — exercises every NIDS + WAF detection rule

Uses Scapy's L2 sendp() with an Ethernet loopback header instead of L3 send().
On Linux, send() (L3) ignores iface= for loopback — sendp() (L2) does not.
The loopback Ethernet header is: dst=src="00:00:00:00:00:00", type=0x0800 (IPv4).
"""

import socket
import threading
import time

try:
    from scapy.all import Ether, IP, TCP, ICMP, Raw, sendp, RandShort
    SCAPY = True
except ImportError:
    SCAPY = False
    print("[!] Scapy not available — Scapy-based simulations will be skipped")

TARGET = "127.0.0.1"
IFACE  = "lo"
# Loopback Ethernet frame header (Linux loopback uses all-zero MACs)
LO_ETH = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=0x0800)
DELAY  = 1.0


def scapy_send(pkt):
    """Send a packet on loopback using L2 sendp so iface is respected."""
    sendp(LO_ETH / pkt, iface=IFACE, verbose=False)


#  Dummy TCP listener on 8080 
def run_listener(port=8080):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((TARGET, port))
        srv.listen(50)
        print(f"[*] Listener up on :{port}")
        while True:
            try:
                c, _ = srv.accept()
                c.recv(4096)
                c.close()
            except Exception:
                pass


#  [1] ICMP ping 
def sim_icmp():
    print("\n[1] ICMP ping → expects Low alert")
    if SCAPY:
        scapy_send(IP(src=TARGET, dst=TARGET) / ICMP())
    print("    done")


#  [2] NULL scan 
def sim_null_scan():
    print("\n[2] NULL scan → expects Medium alert")
    if SCAPY:
        scapy_send(IP(src=TARGET, dst=TARGET) / TCP(dport=80, flags=0))
    print("    done")


#  [3] XMAS scan 
def sim_xmas_scan():
    print("\n[3] XMAS scan → expects Medium alert")
    if SCAPY:
        scapy_send(IP(src=TARGET, dst=TARGET) / TCP(dport=80, flags="FPU"))
    print("    done")


#  [4] Port scan — SYN to non-server ports so engine distinguishes from
#        normal Socket.IO/app traffic on 5000/5001/8080 
def sim_port_scan():
    print("\n[4] Port scan (ports 1024-1043 via Scapy SYN) → expects Medium alert")
    if SCAPY:
        for port in range(1024, 1044):
            scapy_send(IP(src=TARGET, dst=TARGET) /
                       TCP(dport=port, sport=int(RandShort()), flags="S"))
            time.sleep(0.05)
    print("    done")


#  [5] SYN flood 
def sim_syn_flood():
    print("\n[5] SYN flood (25 packets) → expects Critical alert")
    if SCAPY:
        for _ in range(25):
            scapy_send(IP(src=TARGET, dst=TARGET) /
                       TCP(dport=9999, sport=int(RandShort()), flags="S"))
    print("    done")


#  [6] Cleartext credentials 
def sim_cleartext():
    print("\n[6] Cleartext credentials → expects High alert")
    payload = b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 37\r\n\r\nusername=admin&password=secret123"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TARGET, 8080))
            s.sendall(payload)
            time.sleep(0.1)
    except Exception as e:
        print(f"    error: {e}")
    print("    done")


#  [7] SQL keyword in payload 
def sim_sql_payload():
    print("\n[7] SQL keyword in payload → expects High alert")
    if SCAPY:
        payload = b"GET /?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: localhost\r\n\r\n"
        scapy_send(IP(src=TARGET, dst=TARGET) /
                   TCP(dport=8080, sport=int(RandShort()), flags="PA") /
                   Raw(load=payload))
    print("    done")


#  WAF helpers 
def http_post(path, body, ua="Mozilla/5.0", port=5001):
    try:
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: localhost:{port}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((TARGET, port))
            s.sendall(raw.encode())
            s.recv(4096)
    except Exception:
        pass


def sim_waf_sqli():
    print("\n[8] WAF: SQL injection → expects Critical alert")
    http_post("/inspect", "body=' OR 1=1-- &path=/login&method=POST")
    print("    done")


def sim_waf_xss():
    print("\n[9] WAF: XSS → expects High alert")
    http_post("/inspect", "body=<script>alert(document.cookie)</script>&path=/search&method=GET")
    print("    done")


def sim_waf_traversal():
    print("\n[10] WAF: Path traversal → expects Critical alert")
    http_post("/inspect", "path=../../etc/passwd&method=GET&body=")
    print("    done")


def sim_waf_brute():
    print("\n[11] WAF: Brute force login (6 attempts) → expects Critical alert")
    for i in range(6):
        http_post("/login", f"username=admin&password=wrong{i}")
    print("    done")


def sim_waf_scanner():
    print("\n[12] WAF: Malicious scanner UA → expects Critical alert")
    http_post("/inspect", "path=/&method=GET&body=", ua="sqlmap/1.7")
    print("    done")


if __name__ == "__main__":
    threading.Thread(target=run_listener, args=(8080,), daemon=True).start()
    time.sleep(0.3)

    print("=" * 55)
    print(" NIDS + WAF Attack Simulation")
    print(f" Scapy interface: {IFACE}   target: {TARGET}")
    print(" L2 sendp() used — iface is enforced on loopback")
    print(" Make sure both app.py (5000) and waf_app.py (5001)")
    print(" are running before starting this script.")
    print("=" * 55)

    sim_icmp();        time.sleep(DELAY)
    sim_null_scan();   time.sleep(DELAY)
    sim_xmas_scan();   time.sleep(DELAY)
    sim_port_scan();   time.sleep(DELAY)
    sim_syn_flood();   time.sleep(DELAY)
    sim_cleartext();   time.sleep(DELAY)

    # sim_sql_payload(); time.sleep(DELAY)
    # sim_waf_sqli();      time.sleep(DELAY)
    # sim_waf_xss();       time.sleep(DELAY)
    # sim_waf_traversal(); time.sleep(DELAY)
    # sim_waf_brute();     time.sleep(DELAY)
    # sim_waf_scanner();   time.sleep(DELAY)

    print("\n[*] All simulations complete. Check your dashboard.")