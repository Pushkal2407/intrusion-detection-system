#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqueue.h"

struct packetQueue *create_queue(void) {
    // Allocate memory for the queue structure
    struct packetQueue *q = (struct packetQueue *)malloc(sizeof(struct packetQueue));
    if (q == NULL) {
        return NULL;  // Return NULL if memory allocation fails
    }
    // Initialize the queue as empty
    q->head = NULL;
    q->tail = NULL;
    return q;
}

void destroy_queue(struct packetQueue *q) {
    if (q == NULL) return;
    
    // Free all nodes and their packet data
    while (!isempty(q)) {
        struct packetData dummy;
        dequeue(q, &dummy);
        free(dummy.packet);
    }
    // Free the queue structure itself
    free(q);
}

int isempty(struct packetQueue *q) {
    // Queue is empty if it's NULL or has no head node
    return (q == NULL || q->head == NULL);
}

int enqueue(struct packetQueue *q, struct packetData *data) {
    if (q == NULL || data == NULL) return -1;  // Invalid input

    // Create a new node
    struct node *new_node = (struct node *)malloc(sizeof(struct node));
    if (new_node == NULL) {
        return -1;  // Memory allocation failed
    }

    // Copy packet data to the new node
    new_node->item.pkthdr = data->pkthdr;
    new_node->item.packet = malloc(data->pkthdr.caplen);
    if (new_node->item.packet == NULL) {
        free(new_node);
        return -1;  // Memory allocation failed
    }
    memcpy(new_node->item.packet, data->packet, data->pkthdr.caplen);
    new_node->next = NULL;

    // Add the new node to the queue
    if (isempty(q)) {
        // If queue is empty, set both head and tail to the new node
        q->head = new_node;
        q->tail = new_node;
    } else {
        // Otherwise, add to the tail
        q->tail->next = new_node;
        q->tail = new_node;
    }

    return 0;  
}

int dequeue(struct packetQueue *q, struct packetData *data) {
    if (isempty(q) || data == NULL) {
        return -1;  // Queue is empty or data pointer is NULL
    }

    // Remove the head node
    struct node *head_node = q->head;
    q->head = q->head->next;
    if (q->head == NULL) {
        q->tail = NULL;  // Queue is now empty
    }

    // Copy data from the removed node 
    *data = head_node->item;
    free(head_node);  // Free the removed node

    return 0;  
}