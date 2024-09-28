from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# Function to analyze each packet captured
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {packet.summary()}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")

            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    http_data = payload.decode('utf-8', errors='ignore')
                    
                    # Detect HTTP Request
                    if http_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                        lines = http_data.split('\r\n')
                        request_line = lines[0].split()
                        if len(request_line) >= 3:
                            method, path, http_version = request_line[:3]
                            print(f"HTTP Method: {method} | Path: {path} | HTTP Version: {http_version}")
                        
                        # Extract Host header
                        for line in lines[1:]:
                            if line.startswith('Host:'):
                                host = line.split(':', 1)[1].strip()
                                print(f"HTTP Host: {host}")
                                break

                    # Detect HTTP Response
                    elif http_data.startswith('HTTP/'):
                        lines = http_data.split('\r\n')
                        status_line = lines[0].split()
                        if len(status_line) >= 3:
                            http_version, status_code, reason_phrase = status_line[:3]
                            print(f"HTTP Version: {http_version} | Status Code: {status_code} | Reason: {reason_phrase}")
                except UnicodeDecodeError:
                    print("Failed to decode HTTP payload.")
            else:
                print("No Raw layer found in this TCP packet.")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")
        else:
            print("Protocol: Other")

# Capture packets in real-time with a timeout
def start_sniffing(interface, timeout=10):
    print(f"[*] Starting packet sniffing on interface: {interface}")
    # Optional: Apply a BPF filter to capture only HTTP traffic
    sniff(iface=interface, prn=analyze_packet, store=False, filter="tcp port 80")

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface, timeout=10)  # Run for 10 seconds
