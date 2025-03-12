from scapy.all import sniff, IP, TCP, raw
import datetime

def start_nids(socketio):
    print("[*] Packet Sniffer Initialized")

    def process_packets(packets):
        if packet.haslayer(IP):
            src_ip=packet[IP].src
            dst_ip=packet[IP].dst
            proto="TCP" if packet.haslayer(TCP) else "Other"

            alert_data = None

            if packet.haslayer(TCP) and packet[TCP].dport==80:
                payload=str(packet[Raw].load)
                if any(key in payload.lower() for key in ["user", "pass", "login"]): # Meaning access attempts
                    alert_data = {
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "type": "Cleartext Credentials",
                        "severity": "High",
                        "source": src_ip,
                        "message": f"Possible login attempt detected from {src_ip}"
                    }
            
            if alert_data:
                socketio.emit('new_alert', alert_data)
                print(f"[!] Alert Sent: {alert_data['type']}")
            
            sniff(prn=process_packet,store=0)