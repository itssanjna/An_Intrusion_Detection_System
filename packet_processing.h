#ifndef PACKET_PROCESSING_H
#define PACKET_PROCESSING_H

#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* PACKET_PROCESSING_H */
