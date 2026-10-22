import socket
import sys

UDP_IP = "172.21.11.200"
UDP_PORTS = [80, 443, 22, 2000, 2082, 2083, 2086, 2087, 2095, 2096, 5060]
MESSAGE = "Balls"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    payload = MESSAGE.encode('utf-8')
    packet_count = 0
    print("Streaming packets continuously. Press Ctrl+C to stop.")
    
    while True:
        for port in UDP_PORTS:
            sock.sendto(payload, (UDP_IP, port))
            packet_count += 1000
            
            # Print status update every 10,000 packets to avoid slowing down the loop
            ##if packet_count % 10000 == 0:
             ##   print(f"Sent {packet_count} packets so far...", end="\r")
                
except KeyboardInterrupt:
    print(f"\nStopped by user. Total packets sent: {packet_count}")
finally:
    sock.close()
