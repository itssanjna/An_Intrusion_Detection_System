#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "packet_processing.h"
#include "utility.h"
#include "network_capture.h"
#include "synscan_detection.h"
#include "udpscan_detection.h"
#include "xmasscan_detection.h"


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

static int count = 1;
static int flag = 0;

int main(int argc, char **argv) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char filter_exp[] = "tcp[tcpflags] & (tcp-syn) != 0";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int num_packets = 100;

    print_app_banner();

    if (argc == 2) {
        dev = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, num_packets, got_packet, NULL);

    syn();
    udp();
    xmas();

    if (flag) {
        printf("\n\n------------ATTACKED------------\n\n");
    } else {
        printf("\n\n------------SAFE------------\n\n");
    }

    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}
