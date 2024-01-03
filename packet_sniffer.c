// packet_sniffer.c

#include "packet_sniffer.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>

struct PacketCount {
    char source_ip[INET_ADDRSTRLEN];
    unsigned int incoming_count;
    unsigned int outgoing_count;
    struct PacketCount *next;
};

pcap_t *handle;
struct PacketCount *packet_counts = NULL;

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);

    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    struct PacketCount *current = packet_counts;
    struct PacketCount *previous = NULL;
    while (current != NULL && strcmp(current->source_ip, source_ip) != 0) {
        previous = current;
        current = current->next;
    }

    if (current == NULL) {
        current = (struct PacketCount *)malloc(sizeof(struct PacketCount));
        strncpy(current->source_ip, source_ip, INET_ADDRSTRLEN);
        current->incoming_count = 0;
        current->outgoing_count = 0;
        current->next = NULL;

        if (previous == NULL) {
            packet_counts = current;
        } else {
            previous->next = current;
        }
    }

    if (ip_header->saddr == ip_header->daddr) {
        // Incoming packet
        current->incoming_count++;
    } else {
        // Outgoing packet
        current->outgoing_count++;
    }

    printf("\rPackets captured (Incoming: %u, Outgoing: %u)", current->incoming_count, current->outgoing_count);
    fflush(stdout);
}

void start_packet_capture(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return;
    }

    while (1) {
        pcap_dispatch(handle, 0, packet_handler, NULL);
        sleep(1);  // Sleep for 1 second
    }
}

void stop_packet_capture() {
    struct PacketCount *current = packet_counts;
    struct PacketCount *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    pcap_close(handle);
}
