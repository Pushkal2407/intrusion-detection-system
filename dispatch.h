#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

// Initialize worker threads
int create_worker_threads();

// Clean up worker threads
void join_worker_threads();

// Dispatch a packet to the worker queue
int dispatch(const struct pcap_pkthdr *header, 
             const unsigned char *packet,
             int verbose);

#endif // CS241_DISPATCH_H