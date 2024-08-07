#include "analysis.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>

// Mutex variables
pthread_mutex_t syn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ip_array_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t url_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;

// Dynamic Array to store source IP addresses
struct SourceIP {
    char ip[INET_ADDRSTRLEN];
};

// Attack variable declarations
struct SourceIP *sourceIPArray = NULL;
int TotalSYNPackets = 0;
int UniqueIPCount = 0;
int ARPResponses = 0;
int BlackUrl = 0;
int GCount = 0;
int BCount = 0;

void interrupt_handler(int signal) {
    pthread_mutex_lock(&report_mutex);

    // Print intrusion detection report
    printf("\n\nIntrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n", TotalSYNPackets, UniqueIPCount);
    printf("%d ARP responses (cache poisoning)\n", ARPResponses);
    printf("%d URL Blacklist violations (%d google and %d bbc)\n", BlackUrl, GCount, BCount);

    // Free allocated memory for source IP array
    free(sourceIPArray);

    // Unlock the mutex to exit the critical section
    pthread_mutex_unlock(&report_mutex);

    // Exit the program
    exit(EXIT_SUCCESS);
}

// Function to check if an IP address is already in the array
bool isIPInArray(const char *ip) {
    for (int i = 0; i < UniqueIPCount; i++) {
        if (strcmp(ip, sourceIPArray[i].ip) == 0) {
            return true;
        }
    }
    return false;
}

// Packet analysis function
void analyse(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if the packet is an ARP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

        // Check for ARP poisoning
        if (ntohs(arp_hdr->arp_op) == ARPOP_REPLY) {
            pthread_mutex_lock(&arp_mutex);
            ARPResponses++;
            pthread_mutex_unlock(&arp_mutex);
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

        // Check if the packet is a TCP packet
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)((unsigned char *)ip_hdr + (ip_hdr->ip_hl << 2));

            // Check if it is a pure SYN packet
            if (tcp_hdr->th_flags == TH_SYN) {
                pthread_mutex_lock(&syn_mutex);
                TotalSYNPackets++;
                pthread_mutex_unlock(&syn_mutex);

                pthread_mutex_lock(&ip_array_mutex);
                if (!isIPInArray(inet_ntoa(ip_hdr->ip_src))) {
                    // Resize the array and copy the new IP if it is not already present
                    struct SourceIP *temp = realloc(sourceIPArray, (UniqueIPCount + 1) * sizeof(struct SourceIP));
                    if (temp == NULL) {
                        fprintf(stderr, "Memory reallocation error\n");
                        pthread_mutex_unlock(&ip_array_mutex);
                        return;
                    }
                    sourceIPArray = temp;
                    strncpy(sourceIPArray[UniqueIPCount].ip, inet_ntoa(ip_hdr->ip_src), INET_ADDRSTRLEN);
                    sourceIPArray[UniqueIPCount].ip[INET_ADDRSTRLEN - 1] = '\0';
                    UniqueIPCount++;
                }
                pthread_mutex_unlock(&ip_array_mutex);
            }

            // Check for blacklisted URLs
            if (ntohs(tcp_hdr->th_dport) == 80) {
                const unsigned char *payload = (unsigned char *)tcp_hdr + (tcp_hdr->th_off << 2);
                int data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl << 2) - (tcp_hdr->th_off << 2);
                
                if (data_len > 0) {
                    pthread_mutex_lock(&url_mutex);
                    if (memmem(payload, data_len, "Host: www.google.co.uk", 22) != NULL) {
                        printf("Blacklisted URL violation detected\n");
                        printf("Source IP address: %s\n", inet_ntoa(ip_hdr->ip_src));
                        printf("Destination IP address: %s (google)\n", inet_ntoa(ip_hdr->ip_dst));
                        BlackUrl++;
                        GCount++;
                    } else if (memmem(payload, data_len, "Host: www.bbc.co.uk", 19) != NULL) {
                        printf("Blacklisted URL violation detected\n");
                        printf("Source IP address: %s\n", inet_ntoa(ip_hdr->ip_src));
                        printf("Destination IP address: %s (bbc)\n", inet_ntoa(ip_hdr->ip_dst));
                        BlackUrl++;
                        BCount++;
                    }
                    pthread_mutex_unlock(&url_mutex);
                }
            }
        }
    }
}