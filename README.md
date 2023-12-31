# Packet Watch

## Overview

Packet Watch is a program designed to capture and analyze network packets on a specified network interface. It provides detailed information about each captured packet, including source and destination IP addresses, ports, protocol, packet size, and a timestamp.

## Usage

```bash
# Compile the Program
gcc -o packet_sniffer packet_sniffer.c main.c -lpcap

# Run the Packet Sniffer
sudo ./packet_sniffer <interface> <output_file> <packet_count> <filter_expression>

# <interface>: Network interface to sniff packets from (e.g., eth0, wlan0).
# <output_file>: Output file to store packet details.
# <packet_count>: Number of packets to capture (use a large number for continuous capture).
# <filter_expression>: BPF filter expression (optional, can be an empty string).

# Example:
sudo ./packet_sniffer eth0 output.txt 100 ""

# Dependencies:
sudo apt-get update
sudo apt-get install libpcap-dev

# What it looks like

[Wed Dec 27 02:32:22 2023]
Packet captured, size: 166 bytes
    Source IP: 45.90.12.156
    Destination IP: 45.90.12.26
    Source Port: 39396
    Destination Port: 22
    Protocol: Unknown (since its a empty string)

    Condensed information: Packets from 45.90.12.156: 8
