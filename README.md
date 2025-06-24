# 🐍 Network Packet Analyzer (Python)

This is a Python-based packet sniffer that captures and analyzes network traffic in real time using raw sockets. It provides insights into the structure of network packets and how data flows through the network.

---

## 🚀 Features

- Captures Ethernet and IPv4 traffic
- Identifies protocols: TCP, UDP, ICMP
- Displays source/destination MAC and IP addresses
- Extracts and formats payload data
- Helps understand networking protocol basics

---

## 🔧 Requirements

- Python 3.x
- Linux OS (for raw socket access via `AF_PACKET`)
- Run with `sudo`

---

## ▶️ Usage

```bash
sudo python3 sniffer.py
