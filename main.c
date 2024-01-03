// main.c

#include "packet_sniffer.h"
#include <stdlib.h>  // Include this line

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <interface> <output_file> <packet_count> <filter_expression>\n", argv[0]);
        return 1;
    }

    // Print the command-line arguments
    printf("Interface: %s\n", argv[1]);
    printf("Output File: %s\n", argv[2]);
    printf("Packet Count: %s\n", argv[3]);
    printf("Filter Expression: %s\n", argv[4]);

    // Start packet capture
    start_packet_capture(argv[1], argv[2], atoi(argv[3]), argv[4]);
    stop_packet_capture();

    return 0;
}
