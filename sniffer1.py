from termcolor import colored
print(colored("**********Network---Sniffer*******",'green'))
print(colored("*******create by snoopy sugar*******",'red'))


import socket
import struct

import pyfiglet  #banner package
banner=colored(pyfiglet.figlet_format("Network Sniffer"),'green')   #use for banner
print(banner)



def create_sniffer():
    
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return sniffer


def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'destination_mac': mac_format(dest_mac),
        'source_mac': mac_format(src_mac),
        'protocol': socket.htons(proto),
        'data': data[14:]
    }

def mac_format(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)


def parse_ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        'version': version_header_length >> 4,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'source_ip': ipv4_format(src),
        'target_ip': ipv4_format(target),
        'data': data[header_length:]
    }

def ipv4_format(addr):
    return '.'.join(map(str, addr))

                       # Start sniffing
def start_sniffing():
    sniffer = create_sniffer()
    print("[*] Sniffer started...\n")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        eth = parse_ethernet_header(raw_data)

        
        if eth['protocol'] == 8:
            ip = parse_ipv4_packet(eth['data'])

            print(f"\n {ip['source_ip']} → {ip['target_ip']}")
            print(f"   Protocol: {ip['protocol']} | TTL: {ip['ttl']}")
            print(f"   Payload: {ip['data'][:32]}...")  

try:
    start_sniffing()
except KeyboardInterrupt:
    print("\n[!] Sniffing stopped by user.")
