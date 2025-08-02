#   Basic_Network_Sniffer
# 🕵️‍♂️ Basic Network Packet Sniffer (Python)

A simple raw-socket network packet sniffer built with Python. This tool captures and parses live network traffic, providing insights into the underlying protocols and packet structure.
> ⚠️ Requires root privileges to run (due to raw socket usage).
---

## 🚀 Features

- Captures packets using raw sockets (`socket` module)
- Parses Ethernet and IPv4 headers
- Displays:
  - Source and destination IP addresses
  - Protocol type (ICMP, TCP, UDP, etc.)
  - TTL (Time To Live)
  - Raw payload (first 32 bytes)
- Easy to extend for TCP/UDP/ICMP header analysis
---

## 🖥️ Example Output

```text
[*] Sniffer started. Listening for packets...

🌐 192.168.0.118 → 8.8.8.8
   Protocol: 1 | TTL: 64
   Payload: b'\x08\x00\xfeg\x00...'
