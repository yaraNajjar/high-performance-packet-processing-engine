#include "../include/packet_queue.h"
#include <string.h>
#include <stdatomic.h>

/* Initialize queue */
void queue_init(packet_queue_t *q)
{
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
}

/* Enqueue packet (Lock-Free) */
int enqueue(packet_queue_t *q, packet_t *pkt)
{
    int tail = atomic_load(&q->tail);
    int head = atomic_load(&q->head);

    int next = (tail + 1) % MAX_QUEUE;

    /* Queue full */
    if (next == head)
        return -1;

    q->packets[tail] = *pkt;

    atomic_store(&q->tail, next);

    return 0;
}

/* Dequeue single packet */
int dequeue(packet_queue_t *q, packet_t *pkt)
{
    int head = atomic_load(&q->head);
    int tail = atomic_load(&q->tail);

    /* Queue empty */
    if (head == tail)
        return -1;

    *pkt = q->packets[head];

    atomic_store(&q->head, (head + 1) % MAX_QUEUE);

    return 0;
}

/* Batch dequeue (much faster for workers) */
int dequeue_batch(packet_queue_t *q, packet_t *batch, int batch_size)
{
    int head = atomic_load(&q->head);
    int tail = atomic_load(&q->tail);

    int n = 0;

    while (head != tail && n < batch_size) {

        batch[n] = q->packets[head];

        head = (head + 1) % MAX_QUEUE;

        n++;
    }

    atomic_store(&q->head, head);

    return n;
}