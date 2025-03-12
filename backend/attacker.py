# Attacker script for simulation

import socket

target_ip="127.0.0.1"
target_port=80
message = "POST /login HTTP/1.1\r\nHost: localhost\r\n\r\nUSER=admin&PASS=password123"

def simulate_attack():
    print(f"Sending malicious payload to {target_ip}:{target_port}...")
    try:
        # raw socket to mimic a web request
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            s.sendall(message.encode())
        print("Payload sent! Check your NIDS Dashboard.")
    except Exception as e:
        print(f"Connection failed: {e} (This is normal if nothing is listening on Port 80, but the NIDS should still 'see' the attempt)")

if __name__ == "__main__":
    simulate_attack()