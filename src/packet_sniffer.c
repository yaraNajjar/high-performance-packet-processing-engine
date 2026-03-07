#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#include "../include/packet.h"
#include "../include/rules.h"
#include "../include/packet_queue.h"
#include <time.h>

#define NUM_WORKERS 4

int packets_last_second = 0;

/* Worker threads */
pthread_t workers[NUM_WORKERS];

/* Packet queue */
packet_queue_t queue;

/* Firewall rules */
rule_set_t my_rules;

/* Statistics */
int allowed_packets = 0;
int blocked_packets = 0;


/* Packet capture callback */
void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    /* Push packet to queue for workers */
    enqueue(&queue, packet, header->len);
}


/* Worker thread */
void *worker_function(void *arg)
{
    int id = *(int*)arg;
    packet_t pkt;

    while (1) {

        if (dequeue(&queue, &pkt) == 0) {

            struct ethhdr *eth = (struct ethhdr *)pkt.data;

            if (ntohs(eth->h_proto) != ETH_P_IP)
                continue;

            struct iphdr *ip = (struct iphdr *)(pkt.data + sizeof(struct ethhdr));

            uint32_t src_ip = ip->saddr;

            /* Firewall check */
            if (!check_packet(&my_rules, src_ip)) {

                printf("Worker %d blocked packet from IP: %s\n",
                       id,
                       inet_ntoa(*(struct in_addr*)&src_ip));

                blocked_packets++;
                packets_last_second++;
                continue;
            }

            allowed_packets++;
            packets_last_second++;

            printf("\nWorker %d processing packet\n", id);

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

            printf("Packet size: %d bytes\n\n", pkt.length);

            /* Call parser */
            parse_packet(pkt.data);
        }
    }

    return NULL;
}

void *monitor_function(void *arg)
{
    while (1) {
        sleep(1); 
        printf("\n=== Packet Stats (last 1s) ===\n");
        printf("Packets processed: %d pkt/s\n", packets_last_second);
        printf("Allowed packets: %d\n", allowed_packets);
        printf("Blocked packets: %d\n", blocked_packets);
        packets_last_second = 0;
    }
    return NULL;
}

int main()
{
    queue_init(&queue);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev = "eth0";

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("Could not open device %s\n", dev);
        return 1;
    }

    printf("Sniffer started...\n");

    /* Add firewall rule example */
    add_rule(&my_rules, inet_addr("8.8.8.8"), false);

    /* Start worker threads */
    int ids[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        ids[i] = i;
        pthread_create(&workers[i], NULL, worker_function, &ids[i]);
    }

    printf("Workers started: %d\n", NUM_WORKERS);

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, monitor_function, NULL);

    /* Start capturing packets */
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}