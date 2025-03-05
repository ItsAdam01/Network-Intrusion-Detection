from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, get_if_list, conf
import datetime
import time
import queue
import threading
from collections import defaultdict

_event_queue = queue.Queue()

# Ports belonging to our own services — exclude from SYN flood / port scan
OWN_PORTS = {5000, 5001, 8080}

# Per-alert dedup: suppress same (type, src) within TTL seconds
_alert_dedup      = {}
_alert_dedup_lock = threading.Lock()
ALERT_DEDUP_TTL   = 1.5


def _alert_is_dup(alert_type, src):
    key = (alert_type, src)
    now = time.time()
    with _alert_dedup_lock:
        expired = [k for k, t in _alert_dedup.items()
                   if isinstance(t, float) and now - t > ALERT_DEDUP_TTL * 2]
        for k in expired:
            del _alert_dedup[k]
        last = _alert_dedup.get(key)
        if last is not None and now - last < ALERT_DEDUP_TTL:
            return True
        _alert_dedup[key] = now
        return False


def _get_sniff_interfaces():
    """
    Return the interfaces to sniff on:
      - 'lo'   : loopback  — catches attacker.py / local simulation traffic
      - everything else : catches real inbound/outbound network traffic

    Sniff them in two separate threads so neither blocks the other.
    """
    try:
        all_ifaces = get_if_list()
    except Exception:
        all_ifaces = []

    lo_ifaces   = [i for i in all_ifaces if i == "lo"]
    real_ifaces = [i for i in all_ifaces if i != "lo"]

    print(f"[*] Loopback interfaces : {lo_ifaces}")
    print(f"[*] Network interfaces  : {real_ifaces}")
    return lo_ifaces, real_ifaces



def start_nids(socketio):

    _last_stats_emit = [0.0]
    STATS_EMIT_INTERVAL = 1.0  # emit at most once per second

    def _queue_stats_throttled(total, tcp, udp, icmp, other):
        now = time.time()
        if now - _last_stats_emit[0] < STATS_EMIT_INTERVAL:
            return
        _last_stats_emit[0] = now
        _queue_stats(total, tcp, udp, icmp, other)

    print("[*] Full NIDS Engine Initialized")

    emitter = threading.Thread(target=_emitter_loop, args=(socketio,), daemon=True)
    emitter.start()
    print("[*] Emitter thread started")

    # ── Shared state (all sniffer threads write to these) 
    packet_count = 0
    tcp_count    = 0
    udp_count    = 0
    icmp_count   = 0
    other_count  = 0
    state_lock   = threading.Lock()

    port_scan_tracker   = defaultdict(lambda: {"ports": set(), "window_start": time.time()})
    PORT_SCAN_THRESHOLD = 8
    PORT_SCAN_WINDOW    = 30

    syn_flood_tracker        = defaultdict(lambda: {"count": 0, "window_start": time.time()})
    syn_flood_last_alert     = defaultdict(float)
    SYN_FLOOD_THRESHOLD      = 15
    SYN_FLOOD_WINDOW         = 15
    SYN_FLOOD_ALERT_COOLDOWN = 5.0

    arp_table    = defaultdict(set)
    tracker_lock = threading.Lock()

    def make_alert(type_, severity, src, dst, proto, message, extra=None):
        return {
            "timestamp":   datetime.datetime.now().strftime("%H:%M:%S"),
            "type":        type_,
            "severity":    severity,
            "source":      str(src),
            "destination": str(dst),
            "protocol":    str(proto),
            "message":     str(message),
            **(extra or {}),
        }

    def emit_alert(alert):
        try:
            src = alert.get("source", "")
            typ = alert.get("type", "")
            if _alert_is_dup(typ, src):
                return
            print(f"[ALERT] {alert.get('severity','?'):8s} | {typ} | {src}")
            _event_queue.put(("alert", alert))
        except Exception as e:
            print(f"[!] emit_alert error: {e}")

    def process_packet(packet):
        nonlocal packet_count, tcp_count, udp_count, icmp_count, other_count

        try:
            with state_lock:
                packet_count += 1
                local_count = packet_count

            #  ARP Spoofing 
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                sender_ip  = packet[ARP].psrc
                sender_mac = packet[ARP].hwsrc
                with tracker_lock:
                    known_macs = arp_table[sender_ip]
                    if known_macs and sender_mac not in known_macs:
                        emit_alert(make_alert(
                            "ARP Spoofing", "Critical",
                            sender_ip, "broadcast", "ARP",
                            f"ARP cache poisoning: {sender_ip} changed MAC to {sender_mac}",
                            {"flags": "ARP-REPLY"}
                        ))
                    known_macs.add(sender_mac)

            if not packet.haslayer(IP):
                with state_lock:
                    _queue_stats(packet_count, tcp_count, udp_count, icmp_count, other_count)
                return

            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)

            #  Protocol counting 
            with state_lock:
                if packet.haslayer(TCP):
                    tcp_count += 1
                    proto = "TCP"
                elif packet.haslayer(UDP):
                    udp_count += 1
                    proto = "UDP"
                elif packet.haslayer(ICMP):
                    icmp_count += 1
                    proto = "ICMP"
                else:
                    other_count += 1
                    proto = "Other"

            #  TCP 
            if packet.haslayer(TCP):
                tcp      = packet[TCP]
                flags    = int(tcp.flags)
                flag_str = _flags_to_str(flags)
                dst_port = int(tcp.dport)
                src_port = int(tcp.sport)

                # NULL Scan
                if flags == 0x00:
                    emit_alert(make_alert(
                        "NULL Scan", "Medium", src_ip, dst_ip, "TCP",
                        f"NULL scan (no flags) from {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                        {"flags": "NULL"}
                    ))

                # XMAS Scan
                if flags & 0x29 == 0x29:
                    emit_alert(make_alert(
                        "XMAS Scan", "Medium", src_ip, dst_ip, "TCP",
                        f"XMAS scan (FIN+PSH+URG) from {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                        {"flags": flag_str}
                    ))

                # Pure SYN on non-owned ports
                if flags == 0x02 and dst_port not in OWN_PORTS:
                    with tracker_lock:
                        # SYN Flood
                        sf = syn_flood_tracker[src_ip]
                        now = time.time()
                        if now - sf["window_start"] > SYN_FLOOD_WINDOW:
                            sf["count"]        = 0
                            sf["window_start"] = now
                        sf["count"] += 1
                        if sf["count"] >= SYN_FLOOD_THRESHOLD:
                            last_t = syn_flood_last_alert[src_ip]
                            if now - last_t >= SYN_FLOOD_ALERT_COOLDOWN:
                                alert = make_alert(
                                    "SYN Flood", "Critical", src_ip, dst_ip, "TCP",
                                    f"{src_ip} sent {sf['count']} SYN packets in {SYN_FLOOD_WINDOW}s — possible DDoS",
                                    {"flags": flag_str}
                                )
                                print(f"[ALERT] Critical | SYN Flood | {src_ip}")
                                _event_queue.put(("alert", alert))
                                syn_flood_last_alert[src_ip] = now
                            sf["count"] = 0

                        # Port Scan
                        ps = port_scan_tracker[src_ip]
                        now = time.time()
                        if now - ps["window_start"] > PORT_SCAN_WINDOW:
                            ps["ports"]        = set()
                            ps["window_start"] = now
                        ps["ports"].add(dst_port)
                        if len(ps["ports"]) >= PORT_SCAN_THRESHOLD:
                            emit_alert(make_alert(
                                "Port Scan", "Medium", src_ip, dst_ip, "TCP",
                                f"{src_ip} probed {len(ps['ports'])} ports in {PORT_SCAN_WINDOW}s",
                                {"flags": flag_str}
                            ))
                            ps["ports"]        = set()
                            ps["window_start"] = now

                # Payload
                if packet.haslayer(Raw):
                    _inspect_payload(bytes(packet[Raw].load),
                                     src_ip, dst_ip, src_port, dst_port, "TCP",
                                     emit_alert, make_alert)

            #  UDP 
            if packet.haslayer(UDP) and packet.haslayer(Raw):
                _inspect_payload(bytes(packet[Raw].load),
                                 src_ip, dst_ip,
                                 int(packet[UDP].sport), int(packet[UDP].dport), "UDP",
                                 emit_alert, make_alert)

            #  ICMP — Echo Request only 
            if packet.haslayer(ICMP) and int(packet[ICMP].type) == 8:
                emit_alert(make_alert(
                    "ICMP Packet", "Low", src_ip, dst_ip, "ICMP",
                    f"ICMP Echo Request from {src_ip} to {dst_ip}"
                ))

        except Exception as e:
            print(f"[!] process_packet error: {e}")
        finally:
            with state_lock:
                _queue_stats_throttled(packet_count, tcp_count, udp_count, icmp_count, other_count)

    #  Launch sniffers 
    lo_ifaces, real_ifaces = _get_sniff_interfaces()

    def sniff_iface(iface):
        try:
            print(f"[*] Sniffing on: {iface}")
            sniff(prn=process_packet, store=0, iface=iface)
        except PermissionError:
            print(f"[!] Permission denied on {iface} — run with sudo")
        except Exception as e:
            print(f"[!] Sniff error on {iface}: {e}")

    # Loopback in its own thread
    for iface in lo_ifaces:
        t = threading.Thread(target=sniff_iface, args=(iface,), daemon=True)
        t.start()

    # Real interfaces each in their own thread, except the last one
    # which runs on the main engine thread
    if real_ifaces:
        for iface in real_ifaces[:-1]:
            t = threading.Thread(target=sniff_iface, args=(iface,), daemon=True)
            t.start()
        # Last real interface blocks here (keeps engine alive)
        sniff_iface(real_ifaces[-1])
    else:
        # No real interfaces found — just keep the main thread alive
        print("[*] No real network interfaces found — monitoring loopback only")
        threading.Event().wait()


def _queue_stats(total, tcp, udp, icmp, other):
    try:
        _event_queue.put(("stats", {
            "total": int(total),
            "tcp":   int(tcp),
            "udp":   int(udp),
            "icmp":  int(icmp),
            "other": int(other),
            "time":  datetime.datetime.now().strftime("%H:%M:%S"),
        }))
    except Exception as e:
        print(f"[!] _queue_stats error: {e}")


def _emitter_loop(socketio):
    print("[*] Emitter loop running")
    while True:
        try:
            event_type, data = _event_queue.get(timeout=1)
            if event_type == "alert":
                print(f"[EMIT] {data.get('type','?')} ({data.get('severity','?')})")
                socketio.emit('new_alert', data)
            elif event_type == "stats":
                socketio.emit('traffic_stats', data)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[!] Emitter error (non-fatal): {e}")
            continue


def _flags_to_str(flags):
    names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
             0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR"}
    return "+".join(v for k, v in names.items() if flags & k) or "NONE"


SUSPICIOUS_PAYLOADS = [
    (b"username=",    "Cleartext Credentials",  "High"),
    (b"password=",    "Cleartext Credentials",  "High"),
    (b"passwd=",      "Cleartext Credentials",  "High"),
    (b"DROP TABLE",   "SQL Injection Attempt",   "Critical"),
    (b"UNION SELECT", "SQL Keyword in Payload",  "High"),
    (b"SELECT ",      "SQL Keyword in Payload",  "High"),
    (b"UNION ",       "SQL Keyword in Payload",  "High"),
    (b"/etc/passwd",  "Path Traversal",          "Critical"),
    (b"<script>",     "XSS Attempt",             "High"),
    (b"../",          "Directory Traversal",     "Medium"),
    (b"cmd.exe",      "Command Injection",       "Critical"),
    (b"/bin/sh",      "Shell Injection",         "Critical"),
    (b"wget http",    "Remote Download Attempt", "Critical"),
    (b"curl http",    "Remote Download Attempt", "Critical"),
    (b"USER ",        "FTP Credentials",         "Medium"),
    (b"PASS ",        "FTP Credentials",         "Medium"),
]


def _inspect_payload(payload, src_ip, dst_ip, src_port, dst_port, proto,
                     emit_alert, make_alert):
    try:
        payload_lower = payload.lower()
        for pattern, label, severity in SUSPICIOUS_PAYLOADS:
            if pattern.lower() in payload_lower:
                emit_alert({
                    "timestamp":   datetime.datetime.now().strftime("%H:%M:%S"),
                    "type":        label,
                    "severity":    severity,
                    "source":      f"{src_ip}:{src_port}",
                    "destination": f"{dst_ip}:{dst_port}",
                    "protocol":    str(proto),
                    "message":     f"Suspicious pattern '{pattern.decode().strip()}' found in {proto} payload",
                    "flags":       "PAYLOAD",
                })
                break
    except Exception as e:
        print(f"[!] _inspect_payload error: {e}")