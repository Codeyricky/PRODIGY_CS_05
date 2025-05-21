# PRODIGY_CS_05
# Packet Sniffer Tool (Python + Scapy)

This project was developed as part of my internship at **Prodigy InfoTech** under the role of **Cyber Security Intern**.  
The goal was to create a basic **packet sniffer tool** using **Python** and the **Scapy** library to capture and analyze live network traffic.

---

## Description

This tool captures packets from the network interface and displays essential information including:
- Source IP address
- Destination IP address
- Protocol used (TCP, UDP, ICMP, etc.)
- Payload data (optional and can be uncommented for deeper analysis)

The tool demonstrates how network sniffers work at a fundamental level and is intended for educational and authorized testing environments only.

---

## Features

- Real-time packet sniffing
- Displays protocol type and IP addresses
- Filterable and extendable for specific traffic types (e.g., only TCP or HTTP)
- Lightweight and console-based

---

## Important Notice

> This tool is intended **strictly for educational and ethical purposes**.  
> Use it **only on networks you own or have explicit permission to monitor**.  
> Unauthorized sniffing is illegal and unethical.

---

## Requirements

- Python 3.x
- Scapy library

### Installation

Install Scapy using pip:
```bash
pip install scapy
