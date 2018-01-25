#ifndef __PCAP_H__
#define __PCAP_H__

#include <stdbool.h>
#include <sys/queue.h>
#include "queue.h"

struct packet {
	uint8_t *bytes;
	size_t len;
	TAILQ_ENTRY(packet) entries;
};

struct addrlist {
	uint8_t srcaddr[6];
	TAILQ_ENTRY(addrlist) entries;
};

typedef struct CaptureState {
	QueueConnection *q;
	TAILQ_HEAD(addrq, addrlist) addrHead;
} CaptureState;

bool startPacketCapture();
void stopPacketCapture();

void printBuffer(uint8_t *buffer, size_t len);
int countPackets();

#endif
