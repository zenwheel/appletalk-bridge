#ifndef __PCAP_H__
#define __PCAP_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pcap/pcap.h>

pcap_t *openInterface(const char *dev, bool forCapture);
bool startPacketCapture(void);
void stopPacketCapture(void);

// learn the source MAC of a frame we are about to inject, so the capture
// thread never relays traffic from that (remote) device back over the bridge
void rememberRemoteSource(const uint8_t *frame, size_t len);

void printBuffer(const uint8_t *buffer, size_t len);

#endif
