// packet_sniffer.h

#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void start_packet_capture(const char *interface);
void stop_packet_capture();

#endif // PACKET_SNIFFER_H
