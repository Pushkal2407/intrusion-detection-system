#ifndef CS241_PQUEUE_H
#define CS241_PQUEUE_H

#include <pcap.h>

struct packetData {
    struct pcap_pkthdr pkthdr;
    u_char *packet;
};

struct node {
    struct packetData item;
    struct node *next;
};

struct packetQueue {
    struct node *head;
    struct node *tail;
};

struct packetQueue *create_queue(void);
void destroy_queue(struct packetQueue *q);
int isempty(struct packetQueue *q);
int enqueue(struct packetQueue *q, struct packetData *data);
int dequeue(struct packetQueue *q, struct packetData *data);

#endif // CS241_PQUEUE_H