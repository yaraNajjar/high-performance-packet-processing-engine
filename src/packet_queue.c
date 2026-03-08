#include "../include/packet_queue.h"
#include <string.h>
#include <pthread.h>
#include <stdio.h>

void queue_init(packet_queue_t *q)
{
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    pthread_mutex_init(&q->lock, NULL);
}

/* Enqueue a single packet into the queue */
int enqueue(packet_queue_t *q, const unsigned char *data, int length)
{
    pthread_mutex_lock(&q->lock);

    int next = (q->tail + 1) % MAX_QUEUE;

    // Check if queue is full
    if (q->count >= MAX_QUEUE) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    memcpy(q->packets[q->tail].data, data, length);
    q->packets[q->tail].length = length;

    q->tail = next;
    q->count++;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

/* Dequeue a single packet */
int dequeue(packet_queue_t *q, packet_t *pkt)
{
    pthread_mutex_lock(&q->lock);

    if (q->count == 0) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    *pkt = q->packets[q->head];

    q->head = (q->head + 1) % MAX_QUEUE;
    q->count--;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

/* Batch dequeue: dequeue up to batch_size packets at once */
int dequeue_batch(packet_queue_t *q, packet_t *batch, int batch_size)
{
    pthread_mutex_lock(&q->lock);

    int n = 0;
    while (n < batch_size && q->count > 0) {
        batch[n] = q->packets[q->head];
        q->head = (q->head + 1) % MAX_QUEUE;
        q->count--;
        n++;
    }

    pthread_mutex_unlock(&q->lock);
    return n; // return the number of packets dequeued
}