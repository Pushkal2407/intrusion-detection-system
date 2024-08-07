#include "sniff.h"
#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include "dispatch.h"
#include "pqueue.h"

static struct packetQueue *work_queue;

static void packet_handler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int verbose = *((int *)args);
    
    // If verbose mode is on, dump packet details
    if (verbose) {
        dump(packet, pkthdr->len);
    }
    
    // Prepare packet data for dispatch
    struct packetData new_packet;
    new_packet.pkthdr = *pkthdr;
    new_packet.packet = (u_char *)packet;
    
    // Dispatch packet to worker threads
    if (dispatch(&new_packet, verbose) != 0) {
        fprintf(stderr, "Failed to dispatch packet\n");
    }
}

void sniff(char *interface, int verbose) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the network interface for packet capture
    pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }
    printf("SUCCESS! Opened %s for capture\n", interface);
    
    // Create work queue for packet processing
    work_queue = create_queue();
    if (work_queue == NULL) {
        fprintf(stderr, "Failed to create work queue\n");
        pcap_close(pcap_handle);
        exit(EXIT_FAILURE);
    }
    
    // Initialize worker threads
    if (create_worker_threads() != 0) {
        fprintf(stderr, "Failed to create worker threads\n");
        destroy_queue(work_queue);
        pcap_close(pcap_handle);
        exit(EXIT_FAILURE);
    }
    
    // Set up signal handler for graceful termination
    struct sigaction sa;
    sa.sa_handler = interrupt_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to set up signal handler");
        join_worker_threads();
        destroy_queue(work_queue);
        pcap_close(pcap_handle);
        exit(EXIT_FAILURE);
    }
    
    // Start packet capture loop
    if (pcap_loop(pcap_handle, 0, packet_handler, (u_char *)&verbose) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap_handle));
    }
    
    // Clean up resources
    join_worker_threads();
    destroy_queue(work_queue);
    pcap_close(pcap_handle);
}

void dump(const unsigned char *data, int length) {
    unsigned int i;
    static unsigned long pcount = 0;
    
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *) data;
    printf("\n\n === PACKET %ld HEADER ===", pcount);
    
    // Print Source MAC
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    
    // Print Destination MAC
    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    
    printf("\nType: %hu\n", eth_header->ether_type);
    printf(" === PACKET %ld DATA == \n", pcount);
    
    // Decode Packet Data 
    int data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    const static int output_sz = 20; // Output 20 bytes at a time
    
    while (data_bytes > 0) {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
        
        // Print data in raw hexadecimal form
        for (i = 0; i < output_sz; ++i) {
            if (i < output_bytes) {
                printf("%02x ", payload[i]);
            } else {
                printf ("   "); // Maintain padding for partial lines
            }
        }
        
        printf ("| ");
        
        // Print data in ASCII form
        for (i = 0; i < output_bytes; ++i) {
            char byte = payload[i];
            if (byte > 31 && byte < 127) {
                // Printable ASCII range
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        
        printf("\n");
        payload += output_bytes;
        data_bytes -= output_bytes;
    }
    
    pcount++;
}