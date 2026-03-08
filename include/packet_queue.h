#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_QUEUE 1024
#define MAX_PACKET_SIZE 65536

typedef struct {
    unsigned char data[MAX_PACKET_SIZE];
    int length;
} packet_t;

typedef struct {
    packet_t packets[MAX_QUEUE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
} packet_queue_t;

void queue_init(packet_queue_t *q);
int enqueue(packet_queue_t *q, const unsigned char *data, int length);
int dequeue(packet_queue_t *q, packet_t *pkt);
int dequeue_batch(packet_queue_t *q, packet_t *batch, int batch_size);

#endif