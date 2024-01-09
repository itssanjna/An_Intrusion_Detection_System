#include "packet_processing.h"
#include "utility.h"
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number %d:\n", count);
    count++;

    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    if (strcmp("178.x.x.x", inet_ntoa(ip->ip_src)) == 0) {
        flag = 1;
    }
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}
