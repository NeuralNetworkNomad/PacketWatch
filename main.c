// main.c

#include "packet_sniffer.h"

int main() {
    // Start packet capture on interface "eth0," write to "packet_capture.txt," capture 10 packets, and filter for TCP
    start_packet_capture("eth0", "packet_capture.txt", 100, "tcp");
    stop_packet_capture();

    return 0;
}
