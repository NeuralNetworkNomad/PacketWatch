Packet Sniffer Instructions:
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
Explanation:
The packet sniffer is a program that captures and analyzes network packets on a specified network interface. It provides detailed information about each captured packet, including source and destination IP addresses, ports, protocol, packet size, and a timestamp.

Source IP: The IP address of the sender.
Destination IP: The IP address of the recipient.
Source Port: The port number used by the sender.
Destination Port: The port number used by the recipient.
Protocol: The network protocol used (TCP, UDP, or Unknown).
Packet Size: The size of the captured packet in bytes.
Timestamp: The timestamp indicating when the packet was captured.
Dependencies:
If your system lacks the necessary libraries, you might need to install them. Use the following commands based on your Linux distribution:

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
Make sure to run these commands before compiling the packet sniffer to ensure that the required libraries are installed.

Feel free to customize the filter expression based on your specific needs. If you have any issues or questions, please let me know!
