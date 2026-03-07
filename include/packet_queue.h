#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <pthread.h>

#define MAX_QUEUE 1024
#define MAX_PACKET_SIZE 2048

typedef struct {
    unsigned char data[MAX_PACKET_SIZE];
    int length;
} packet_t;

typedef struct {
    packet_t packets[MAX_QUEUE];
    int head;
    int tail;
    pthread_mutex_t lock;
} packet_queue_t;

void queue_init(packet_queue_t *q);
int enqueue(packet_queue_t *q, const unsigned char *data, int length);
int dequeue(packet_queue_t *q, packet_t *pkt);

#endif