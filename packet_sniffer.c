// packet_sniffer.c

#include "packet_sniffer.h"
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>

struct PacketCount {
    char source_ip[INET_ADDRSTRLEN];
    unsigned int count;
    struct PacketCount *next;
};

pcap_t *handle;
FILE *output_file;
struct PacketCount *packet_counts = NULL;

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);

    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    unsigned short *source_port = (unsigned short *)(packet + 14 + (ip_header->ihl << 2));
    unsigned short *dest_port = (unsigned short *)(packet + 14 + (ip_header->ihl << 2) + 2);

    unsigned char protocol = *(packet + 14 + (ip_header->ihl << 2) + 9);

    struct PacketCount *current = packet_counts;
    struct PacketCount *previous = NULL;
    while (current != NULL && strcmp(current->source_ip, source_ip) != 0) {
        previous = current;
        current = current->next;
    }

    if (current == NULL) {
        current = (struct PacketCount *)malloc(sizeof(struct PacketCount));
        strncpy(current->source_ip, source_ip, INET_ADDRSTRLEN);
        current->count = 0;
        current->next = NULL;

        if (previous == NULL) {
            packet_counts = current;
        } else {
            previous->next = current;
        }
    }

    current->count++;

    printf("\rPackets from %s: %u    ", source_ip, current->count);
    fflush(stdout);

    time_t timestamp = pkthdr->ts.tv_sec;
    fprintf(output_file, "[%s] Packet captured, size: %d bytes\n", ctime(&timestamp), pkthdr->len);
    fprintf(output_file, "    Source IP: %s\n", source_ip);
    fprintf(output_file, "    Destination IP: %s\n", dest_ip);
    fprintf(output_file, "    Source Port: %d\n", ntohs(*source_port));
    fprintf(output_file, "    Destination Port: %d\n", ntohs(*dest_port));
    fprintf(output_file, "    Protocol: %s\n", (protocol == 6) ? "TCP" : ((protocol == 17) ? "UDP" : "Unknown"));
    fprintf(output_file, "\n");
    fprintf(output_file, "    Condensed information: Packets from %s: %u\n\n", source_ip, current->count);

    if (packet_counts != NULL) {
        struct PacketCount *temp = packet_counts;
        packet_counts = packet_counts->next;
        free(temp);
    }
}



void start_packet_capture(const char *interface, const char *output_file_name, int packet_count, const char *filter_expression) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_expression, pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_expression, pcap_geterr(handle));
        return;
    }

    output_file = fopen(output_file_name, "w");
    if (output_file == NULL) {
        fprintf(stderr, "Could not open output file for writing\n");
        return;
    }

    pcap_loop(handle, packet_count, packet_handler, NULL);

    pcap_close(handle);
    fclose(output_file);
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
    fclose(output_file);
}
