Packet Sniffer
Overview
The Packet Sniffer is a program designed to capture and analyze network packets on a specified network interface. It provides detailed information about each captured packet, including source and destination IP addresses, ports, protocol, packet size, and a timestamp.

Usage
Compile the Program:
bash
Copy code
gcc -o packet_sniffer packet_sniffer.c main.c -lpcap
Run the Packet Sniffer:
bash
Copy code
sudo ./packet_sniffer <interface> <output_file> <packet_count> <filter_expression>
<interface>: Network interface to sniff packets from (e.g., eth0, wlan0).
<output_file>: Output file to store packet details.
<packet_count>: Number of packets to capture (use a large number for continuous capture).
<filter_expression>: BPF filter expression (optional, can be an empty string).
Example:

bash
Copy code
sudo ./packet_sniffer eth0 output.txt 100 ""
Stop the Packet Sniffer:
Use Ctrl+C to stop the packet sniffer gracefully.
Dependencies
Ensure that the necessary library is installed before compiling the packet sniffer:

For Ubuntu/Debian:

bash
Copy code
sudo apt-get update
sudo apt-get install libpcap-dev
For Fedora:

bash
Copy code
sudo dnf install libpcap-devel
For CentOS/RHEL:

bash
Copy code
sudo yum install libpcap-devel
Customization
Feel free to customize the filter expression based on your specific needs. If you encounter any issues or have questions, please let me know!
