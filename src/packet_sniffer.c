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
#include <sched.h>

#include "../include/packet.h"
#include "../include/rules.h"
#include "../include/packet_queue.h"

#define NUM_WORKERS 4
#define BATCH_SIZE 64  // Number of packets to process per worker batch

/* --------------------------- Global Variables --------------------------- */

/* Worker threads */
pthread_t workers[NUM_WORKERS];

/* Monitoring thread */
pthread_t monitor_thread;

/* Packet queue */
packet_queue_t queue;

/* Firewall rules */
rule_set_t my_rules;

/*cach-line aligned counters (avoid false sharing)*/
typedef struct {
    int value;
    char padding[60];
} counter_t;

counter_t allowed_packets = {0};
counter_t blocked_packets = {0};
counter_t packets_last_second = {0};

/* Packets per second counter */
int total_packets = 0;
time_t start_time;

/* Benchmark variables */
int benchmark_mode = 0; // 0 = NEW system, 1 = OLD system
int total_packets_old = 0;

/* Latency statistics */
long latency_total = 0;
long latency_min = 1000000000;
long latency_max = 0;
long latency_count = 0;

/* --------------------------- Packet Handler (NEW SYSTEM) --------------------------- */
/* Capture -> Queue -> Worker threads */
void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    packet_t pkt;

    /* Copy packet into reusable buffer */
    memcpy(pkt.data, packet, header->len);
    pkt.length = header->len;

    clock_gettime(CLOCK_MONOTONIC, &pkt.timestamp);

    /* Enqueue packet for workers */
    enqueue(&queue, &pkt);

    total_packets++;

    /* Packets per second counter */
    time_t current_time = time(NULL);
    if (current_time - start_time >= 1) {
        printf("Packets per second: %d\n", total_packets);
        
        total_packets = 0;
        start_time = current_time;
    }
}

/* --------------------------- Packet Handler (OLD SYSTEM) --------------------------- */
/* Capture -> Process directly (no queue, no workers) */
void packet_handler_old(unsigned char *args,
                        const struct pcap_pkthdr *header,
                        const unsigned char *packet)
{
    total_packets_old++;

    struct ethhdr *eth = (struct ethhdr *)packet;

    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;

    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    uint32_t src_ip = ip->saddr;

    /* Firewall check */
    if (!check_packet(&my_rules, src_ip)) {
        blocked_packets.value++;
        return;
    }

    allowed_packets.value++;

    parse_packet(packet);
}

/* --------------------------- Worker Thread --------------------------- */
/* Each worker processes packets from the queue using batching */
void *worker_function(void *arg)
{
    int id = *(int*)arg;
    free(arg);

    packet_t batch[BATCH_SIZE];
    int batch_count;

    while (1) {

        batch_count = dequeue_batch(&queue, batch, BATCH_SIZE);

        if (batch_count == 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < batch_count; i++) {

            struct ethhdr *eth = (struct ethhdr *)batch[i].data;

            if (ntohs(eth->h_proto) != ETH_P_IP)
                continue;

            struct iphdr *ip = (struct iphdr *)(batch[i].data + sizeof(struct ethhdr));
            uint32_t src_ip = ip->saddr;

            /* Firewall check */
            if (!check_packet(&my_rules, src_ip)) {

                //printf("Worker %d blocked packet from IP: %s\n",
                //       id, inet_ntoa(*(struct in_addr*)&src_ip));

                __sync_fetch_and_add(&blocked_packets.value, 1);
                __sync_fetch_and_add(&packets_last_second.value, 1);
                
                continue;
            }

            __sync_fetch_and_add(&allowed_packets.value, 1);
            __sync_fetch_and_add(&packets_last_second.value, 1);

 /*           printf("\nWorker %d processing packet\n", id);

            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
            printf("Packet size: %d bytes\n\n", batch[i].length);*/

            // Parse packet
            parse_packet(batch[i].data);

            struct timespec end;
            
            /* Measure latency */
            clock_gettime(CLOCK_MONOTONIC, &end);

            long latency_ns =
                (end.tv_sec - batch[i].timestamp.tv_sec) * 1000000000L +
                (end.tv_nsec - batch[i].timestamp.tv_nsec);

            long latency_us = latency_ns / 1000;

            /* Update latency statistics */
            __sync_fetch_and_add(&latency_total, latency_us);
            __sync_fetch_and_add(&latency_count, 1);

            /* Update min */
            if (latency_us < latency_min)
                latency_min = latency_us;

            /* Update max */
            if (latency_us > latency_max)
                latency_max = latency_us;
            
            if (!benchmark_mode) {
                printf("Packet latency: %ld microseconds\n", latency_us);
            }
        }
    }

    return NULL;
}

/* --------------------------- Monitoring Thread --------------------------- */
/* Prints statistics every second */
void *monitor_function(void *arg)
{
    while (1) {

        sleep(1);

        int pkt_last_sec = packets_last_second.value;
        int allowed = allowed_packets.value;
        int blocked = blocked_packets.value;

        long avg = 0;
        if (latency_count > 0)
            avg = latency_total / latency_count;

        printf("\nPackets processed: %d pkt/s\n", pkt_last_sec);
        printf("Allowed packets: %d\n", allowed);
        printf("Blocked packets: %d\n", blocked);

        if (latency_count > 0) {
            printf("Latency avg: %ld us, min: %ld us, max: %ld us\n",
                   avg, latency_min, latency_max);
        }

        /* reset counters for next interval */
        packets_last_second.value = 0;

        latency_total = 0;
        latency_count = 0;
        latency_min = 1000000000;
        latency_max = 0;
    }

    return NULL;
}

/* --------------------------- Main --------------------------- */

int main(int argc, char *argv[])
{
    queue_init(&queue);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "eth0";

    /* Detect benchmark mode */
    if (argc > 1 && strcmp(argv[1], "old") == 0) {
        benchmark_mode = 1;
        printf("Running OLD system benchmark\n");
    } else {
        printf("Running NEW system benchmark\n");
    }

    /* Open network device */
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s\n", dev);
        return 1;
    }

    printf("Packet sniffer started on %s...\n", dev);

    /* Example firewall rule */
    add_rule(&my_rules, inet_addr("8.8.8.8"), false);

    /* Start workers ONLY in new system */
    if (!benchmark_mode) {

        for (int i = 0; i < NUM_WORKERS; i++) {
            int *id = malloc(sizeof(int));
            *id = i;

            pthread_create(&workers[i], NULL, worker_function, id);
        }

        printf("Workers started: %d\n", NUM_WORKERS);

        pthread_create(&monitor_thread, NULL, monitor_function, NULL);
    }

    start_time = time(NULL);

    /* Start packet capture */
    time_t test_start = time(NULL);

    while (time(NULL) - test_start < 60) {

        if (benchmark_mode){
            pcap_dispatch(handle, 10, packet_handler_old, NULL);
        }else{
            pcap_dispatch(handle, 100, packet_handler, NULL);
        }
    }

    printf("\n=== Benchmark Results ===\n");

    int duration = 60; // test duration in seconds

    if (benchmark_mode) {

        printf("System: OLD (single-thread processing)\n");
        printf("Total packets captured: %d\n", total_packets_old);
        printf("Average PPS: %d\n", total_packets_old / duration);

    } else {

        int total_new = allowed_packets.value + blocked_packets.value;

        printf("System: NEW (queue + workers + batching)\n");
        printf("Total packets processed: %d\n", total_new);
        printf("Allowed packets: %d\n", allowed_packets.value);
        printf("Blocked packets: %d\n", blocked_packets.value);
        printf("Average PPS: %d\n", total_new / duration);
    }
    pcap_close(handle);

    return 0;
}