/* Little Sniffer (lsniff)
   Kyle Hale 2011
*/

#include "lsniff.h"



static char * pname;



static void termhandler (int sig) {
    printf("\nRecieved SIGTERM(%d)\nExiting...\n\n", sig);
    exit(0);
}


static void inthandler (int sig) {
    printf("\nReceived SIGINT(%d)\nExiting...\n\n", sig);
    exit(0);
}


static void printUsage (void) {
    fprintf(stderr, "\n=============== LSNIFF ================\n");
    fprintf(stderr, "Usage: %s [options]\n", pname);
    fprintf(stderr, "Options\n");
    fprintf(stderr, "  -d <device>\tspecify capture device\n");
    fprintf(stderr, "  -f <filter-expression>\tapply a filter (see tcpdump)\n");
    fprintf(stderr, "  -c <count>\tOptional number of packets to capture\n");
    fprintf(stderr, "  -h \tDisplay this message\n");
    fprintf(stderr, "========================================\n\n");
}


static void print_hex (const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("\t%05d   ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}


static void print_payload (const u_char * payload, int len) {
    
    int len_r = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char * ch = payload;

    if (len <= 0) 
        return;

    if (len <= line_width) {
        print_hex(ch, len, offset);
        return;
    }


    while (1) {
        /* compute line length */
        line_len = line_width % len_r;
        /* print line */ 
        print_hex(ch, line_len, offset);
        /* compute remaining */
        len_r -= line_len;
        /* point to remaining bytes */
        ch += line_len;
        /* add offset */
        offset += line_width;
        /* check if we have less than line width chars less */
        if (len_r <= line_width) {
            print_hex(ch, len_r, offset);
            break;
        }
    }

    return;
}


void packet_handler (u_char * args, const struct pcap_pkthdr * hdr, const u_char * pkt) {
    
    static int count = 1;

    const struct lsniff_eth *eth; /* eth hdr */
    const struct lsniff_ip *ip; /* IP hdr */
    const struct lsniff_tcp *tcp; /* TCP hdr */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;
    u_int size_payload;

    printf("\nReceiving packet #%d:\n\n", count);
    count++;

    eth = (struct lsniff_eth*)(pkt);
    ip = (struct lsniff_ip*)(pkt + SIZE_ETH);


    /* get the (variable) size of the ip header */
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("Invalid size for IP header: %uB\n", size_ip);
        return;
    }

    printf("\tSrc IP: %s\n", inet_ntoa(ip->ip_src));
    printf("\tDst IP: %s\n", inet_ntoa(ip->ip_dst));

    /* which protocol are we using */
    printf("\tUsing Protocol ");
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("ICMP\n");
            return;
        case IPPROTO_IP:
            printf("IP\n");
            return;
        default:
            printf("Unknown\n");
            return;
    }
    
    tcp = (struct lsniff_tcp*)(pkt + SIZE_ETH + size_ip);

    /* get the (variable) size of the tcp header */
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("Invalid size for TCP header: %uB\n", size_tcp);
        return;
    }

    printf("\tSrc port: %d\n", ntohs(tcp->th_sport));
    printf("\tDst port: %d\n", ntohs(tcp->th_dport));

    /* compute the address of the payload */
    payload = (u_char*)(pkt + SIZE_ETH + size_ip + size_tcp);

    /* then the size of the payload (size of ip segment minus ip & tcp headers)*/
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    /* print out the payload */  
    if (size_payload > 0) {
        printf("\tPayload data (%d Bytes):\n\n", size_payload);
        print_payload(payload, size_payload);
    }
    
    printf("\t--- END PACKET ---\n\n");
    return;
}


int main (int argc, char * argv[]) {

    pname = argv[0];
    char * dev, errbuf[PCAP_ERRBUF_SIZE];
    char * filter_expr = "";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int packet_cnt;
	
    

    /* register our signal handlers */
    signal(SIGINT, inthandler);
    signal(SIGTERM, termhandler);
    
    /* parse our command line args */
    while ((argc > 1) && (argv[1][0] == '-')) {

        switch (argv[1][1]) {
            case 'h':
                printUsage();
                exit(0);
                break;
            case 'd':
                dev = *(argv + 2);
                break;
            case 'f':
                filter_expr = *(argv + 2);
                break;
            case 'c':
                packet_cnt = atoi(*(argv + 2));
                break;
            default:
                fprintf(stderr, "Bad option %s\n", argv[1]);
                printUsage();
                exit(1);
        }
        
        argv += 2;
        argc -= 2;
    }


    /* lookup the default network device */
    if (dev == NULL)
        dev = pcap_lookupdev(errbuf);
    
    /* -1 here means we'll keep capturing until there's an error */
    if (!packet_cnt) 
        packet_cnt = -1;

    if (dev == NULL) {
        fprintf(stderr, "Device discovery failed: %s\n\n", errbuf);
        printUsage();
        exit(1);
    }

    printf("Capturing on device: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Failed to obtain netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    /* open the device in __non-promiscuous__ mode */
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s for capture: %s\n", dev, errbuf);
        printUsage();
        exit(1);
    }

    /* compile our filter*/
    if (pcap_compile(handle, &fp, filter_expr, 0, net) == -1) {
        fprintf(stderr, "Failed to parse filter %s: %s\n", filter_expr, pcap_geterr(handle));
        exit(1);
    }

    /* apply our filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set filter %s: %s\n", filter_expr, pcap_geterr(handle));
        exit(1);
    }

    /* begin capture */
    /*       device    #packets    callback       N/A */
    pcap_loop(handle, packet_cnt, packet_handler, NULL);

    /* close the device */
    pcap_close(handle);
    return 0;
}

