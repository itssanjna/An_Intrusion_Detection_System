#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet frame

    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2));

        if (ntohs(udp_header->len) == 8) {
            printf("Potential UDP Scan detected from %s to %s\n", 
                inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        }
    }
}

int udp() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); // Replace "eth0" with your network interface
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    return 0;
}
