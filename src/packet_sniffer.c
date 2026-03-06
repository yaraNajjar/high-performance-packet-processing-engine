#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    printf("\nPacket captured!\n");

    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_source[0],
           eth->h_source[1],
           eth->h_source[2],
           eth->h_source[3],
           eth->h_source[4],
           eth->h_source[5]);

    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_dest[0],
           eth->h_dest[1],
           eth->h_dest[2],
           eth->h_dest[3],
           eth->h_dest[4],
           eth->h_dest[5]);

    printf("Source IP: %s\n",
       inet_ntoa(*(struct in_addr *)&ip->saddr));

    printf("Destination IP: %s\n",
       inet_ntoa(*(struct in_addr *)&ip->daddr));
       
    printf("Packet size: %d bytes\n\n", header->len);
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev = "eth0";

    handle = pcap_open_live(dev , 65536 , 1 , 1000 , errbuf);

    if(handle == NULL){
        printf("Could not open device %s\n", dev);
        return 1;
    }

    printf("Sniffer started...\n");

    pcap_loop(handle , -1 , packet_handler , NULL);

    pcap_close(handle);

    return 0;
}