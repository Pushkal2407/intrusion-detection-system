#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"
#include "sniff.h"
#include <pthread.h>
#include "pqueue.h"
#include <stdlib.h>
#include <string.h>

#define THREAD_COUNT 10

// Global variables for thread management
static pthread_t worker_threads[THREAD_COUNT];
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_condition = PTHREAD_COND_INITIALIZER;
static int stop_threads = 0;
static struct packetQueue *work_queue = NULL;

void *worker_thread(void *arg) {
    while (1) {
        pthread_mutex_lock(&queue_mutex);
        
        // Wait for work or stop signal
        while (isempty(work_queue) && !stop_threads) {
            pthread_cond_wait(&queue_condition, &queue_mutex);
        }
        
        // Check if it's time to exit
        if (stop_threads && isempty(work_queue)) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        // Dequeue a packet
        struct packetData packet_payload;
        if (dequeue(work_queue, &packet_payload) != 0) {
            pthread_mutex_unlock(&queue_mutex);
            continue;
        }
        
        pthread_mutex_unlock(&queue_mutex);
        
        // Process the packet
        analyse(&packet_payload.pkthdr, packet_payload.packet, 1);
        
        // Free the packet data
        free(packet_payload.packet);
    }
    
    return NULL;
}

int create_worker_threads() {
    // Create the work queue
    work_queue = create_queue();
    if (work_queue == NULL) {
        return -1;
    }
    
    // Create worker threads
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&worker_threads[i], NULL, worker_thread, NULL) != 0) {
            // Clean up on error
            for (int j = 0; j < i; j++) {
                pthread_cancel(worker_threads[j]);
                pthread_join(worker_threads[j], NULL);
            }
            destroy_queue(work_queue);
            return -1;
        }
    }
    return 0;
}

void join_worker_threads() {
    // Signal all threads to stop
    pthread_mutex_lock(&queue_mutex);
    stop_threads = 1;
    pthread_cond_broadcast(&queue_condition);
    pthread_mutex_unlock(&queue_mutex);
    
    // Wait for all threads to finish
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    // Clean up the work queue
    destroy_queue(work_queue);
}

int dispatch(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    // Create a new packet structure
    struct packetData new_packet;
    new_packet.pkthdr = *header;
    new_packet.packet = malloc(header->caplen);
    if (new_packet.packet == NULL) {
        return -1;
    }
    memcpy(new_packet.packet, packet, header->caplen);
    
    // Add the packet to the work queue
    pthread_mutex_lock(&queue_mutex);
    if (enqueue(work_queue, &new_packet) != 0) {
        pthread_mutex_unlock(&queue_mutex);
        free(new_packet.packet);
        return -1;
    }
    pthread_cond_signal(&queue_condition);
    pthread_mutex_unlock(&queue_mutex);
    
    return 0;
}