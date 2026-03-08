#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "../include/packet.h"
#include "../include/rules.h"
#include "../include/packet_queue.h"

#define NUM_WORKERS 4
#define BATCH_SIZE 10  // Number of packets to process per worker batch

/* --------------------------- Global Variables --------------------------- */

/* Worker threads */
pthread_t workers[NUM_WORKERS];

/* Monitoring thread */
pthread_t monitor_thread;

/* Packet queue */
packet_queue_t queue;

/* Firewall rules */
rule_set_t my_rules;

/* Statistics */
int allowed_packets = 0;
int blocked_packets = 0;
int packets_last_second = 0;
int total_packets = 0;
time_t start_time;

/* --------------------------- Packet Handler --------------------------- */
/* This function is called by libpcap for every captured packet.
   Instead of processing directly, we copy the packet into a reusable buffer
   and enqueue it to the packet queue for worker threads (memory reuse + batching) */
void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    packet_t pkt;

    // Copy captured packet data into reusable memory buffer
    memcpy(pkt.data, packet, header->len);
    pkt.length = header->len;

    // Enqueue packet into the queue
    enqueue(&queue, pkt.data, pkt.length);

    // Update total captured packets for general statistics
    total_packets++;

    // Print packets per second every 1 second
    time_t current_time = time(NULL);
    if (current_time - start_time >= 1) {
        printf("Packets per second: %d\n", total_packets);
        total_packets = 0;
        start_time = current_time;
    }
}

/* --------------------------- Worker Thread --------------------------- */
/* Each worker thread dequeues a batch of packets and processes them */
void *worker_function(void *arg)
{
    int id = *(int*)arg;
    packet_t batch[BATCH_SIZE];
    int batch_count;

    while (1) {
        // Dequeue a batch of packets
        batch_count = dequeue_batch(&queue, batch, BATCH_SIZE);
        if (batch_count == 0) {
            usleep(1000); 
            continue;
        }

        for (int i = 0; i < batch_count; i++) {
            struct ethhdr *eth = (struct ethhdr *)batch[i].data;

            // Only process IPv4 packets
            if (ntohs(eth->h_proto) != ETH_P_IP)
                continue;

            struct iphdr *ip = (struct iphdr *)(batch[i].data + sizeof(struct ethhdr));
            uint32_t src_ip = ip->saddr;

            // Firewall check
            if (!check_packet(&my_rules, src_ip)) {
                printf("Worker %d blocked packet from IP: %s\n",
                       id, inet_ntoa(*(struct in_addr*)&src_ip));
                blocked_packets++;
                packets_last_second++;
                continue;
            }

            allowed_packets++;
            packets_last_second++;

            // Print packet info
            printf("\nWorker %d processing packet\n", id);
            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
            printf("Packet size: %d bytes\n\n", batch[i].length);

            // Call packet parser
            parse_packet(batch[i].data);
        }
    }

    return NULL;
}

/* --------------------------- Monitoring Thread --------------------------- */
/* Prints statistics every second: packets processed, allowed, blocked */
void *monitor_function(void *arg)
{
    while (1) {
        sleep(1); // every 1 second
        printf("\n=== Packet Stats (last 1s) ===\n");
        printf("Packets processed: %d pkt/s\n", packets_last_second);
        printf("Allowed packets: %d\n", allowed_packets);
        printf("Blocked packets: %d\n", blocked_packets);
        packets_last_second = 0;
    }
    return NULL;
}

/* --------------------------- Main --------------------------- */
int main()
{
    queue_init(&queue);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "eth0";

    // Open device for live packet capture
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s\n", dev);
        return 1;
    }

    printf("Packet sniffer started on %s...\n", dev);

    // Add example firewall rule: block 8.8.8.8
    add_rule(&my_rules, inet_addr("8.8.8.8"), false);

    // Start worker threads
    int ids[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        ids[i] = i;
        pthread_create(&workers[i], NULL, worker_function, &ids[i]);
    }
    printf("Workers started: %d\n", NUM_WORKERS);

    // Start monitoring thread
    pthread_create(&monitor_thread, NULL, monitor_function, NULL);

    start_time = time(NULL);

    // Start packet capture loop (infinite)
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup (unreachable in current infinite loop)
    pcap_close(handle);

    return 0;
}