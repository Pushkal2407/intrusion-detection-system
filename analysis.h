#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <signal.h>
#include <stdbool.h>

// Define the SourceIP struct
struct SourceIP {
    char ip[INET_ADDRSTRLEN];
};

// Declare external variables
extern struct SourceIP *sourceIPArray;
extern int TotalSYNPackets;
extern int UniqueIPCount;
extern int ARPResponses;
extern int BlackUrl;
extern int GCount;
extern int BCount;

// Function prototypes
void analyse(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose);
void interrupt_handler(int signum);
bool isIPInArray(const char *ip);

#endif // CS241_ANALYSIS_H