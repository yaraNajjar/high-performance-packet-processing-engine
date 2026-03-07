#include "../include/packet_queue.h" 
#include <string.h>

void queue_init(packet_queue_t *q)
{
    q->head = 0;
    q->tail = 0;
    pthread_mutex_init(&q->lock, NULL);
}

int enqueue(packet_queue_t *q, const unsigned char *data, int length)
{
    pthread_mutex_lock(&q->lock);

    int next = (q->tail + 1) % MAX_QUEUE;

    if (next == q->head) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    memcpy(q->packets[q->tail].data, data, length);
    q->packets[q->tail].length = length;

    q->tail = next;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

int dequeue(packet_queue_t *q, packet_t *pkt)
{
    pthread_mutex_lock(&q->lock);

    if (q->head == q->tail) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    *pkt = q->packets[q->head];

    q->head = (q->head + 1) % MAX_QUEUE;

    pthread_mutex_unlock(&q->lock);
    return 0;
}