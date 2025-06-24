import socket
import struct
import textwrap

def format_mac(mac_bytes):
    return ':'.join(format(b, '02x') for b in mac_bytes)

def format_ip(ip_bytes):
    return socket.inet_ntoa(ip_bytes)

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]

def parse_ipv4_header(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return format_ip(src), format_ip(target), proto, data[header_length:]

def parse_tcp_header(data):
    src_port, dest_port = struct.unpack('!HH', data[:4])
    offset = (data[12] >> 4) * 4
    return src_port, dest_port, data[offset:]

def parse_udp_header(data):
    src_port, dest_port = struct.unpack('!HH', data[:4])
    return src_port, dest_port, data[8:]

def parse_icmp(data):
    icmp_type, code = struct.unpack('!BB', data[:2])
    return icmp_type, code, data[4:]

def format_payload(data):
    return '\n'.join(textwrap.wrap(str(data), 80))

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("📡 Listening for packets... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
            print(f"\n  Ethernet Frame: {src_mac} -> {dest_mac} | Protocol: {eth_proto}")

            if eth_proto == 8:  # IPv4
                src_ip, dest_ip, proto, ip_data = parse_ipv4_header(data)
                print(f" IPv4 Packet: {src_ip} -> {dest_ip} | Protocol: {proto}")

                if proto == 6:  # TCP
                    src_port, dest_port, payload = parse_tcp_header(ip_data)
                    print(f" TCP Segment: {src_port} -> {dest_port}")
                elif proto == 17:  # UDP
                    src_port, dest_port, payload = parse_udp_header(ip_data)
                    print(f" UDP Segment: {src_port} -> {dest_port}")
                elif proto == 1:  # ICMP
                    icmp_type, code, payload = parse_icmp(ip_data)
                    print(f"  ICMP Packet: Type {icmp_type}, Code {code}")
                else:
                    payload = ip_data

                print(f"  Payload (first 100 bytes):\n{format_payload(payload[:100])}")
                print("-" * 80)

    except KeyboardInterrupt:
        print("\n  Packet capture stopped.")

if __name__ == "__main__":
    main()
