#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
extern struct packetQueue *work_queue;
#endif
