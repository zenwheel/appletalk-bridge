#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <stdint.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include "pcap.h"
#include "ddp.h"
#include "log.h"
#include "settings.h"
#include "queue.h"

/* adapted from http://www.synack.net/~bbraun/abridge.html */

TAILQ_HEAD(lastq, packet) packetHead;

extern bool m_run;
pthread_t captureThread;
pthread_mutex_t captureMutex;
pcap_t *pcapHandle = 0;
CaptureState *pcapState = 0;

void printBuffer(uint8_t *buffer, size_t len) {
	for(size_t i = 0; i < len; i++) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
}

int countPackets() {
	struct packet *np;
	int result = 0;
	for (np = packetHead.tqh_first; np != NULL; np = np->entries.tqe_next)
		result++;
	return result;
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	CaptureState *state = (CaptureState*)args;

	pthread_mutex_lock(&captureMutex);
	struct packet *np;
	for (np = packetHead.tqh_first; np != NULL; np = np->entries.tqe_next) {
		if(np->len == header->caplen) {
			if(memcmp(packet, np->bytes, header->caplen) == 0 ) {
				free(np->bytes);
				TAILQ_REMOVE(&packetHead, np, entries);
				free(np);
				pthread_mutex_unlock(&captureMutex);
				logDebug("packetHandler returned, skipping our own packet");
				return;
			}
		}
	}
	pthread_mutex_unlock(&captureMutex);

	// anything less than this isn't a valid frame
	if(header->caplen < 18) {
		logError("packetHandler returned, skipping invalid packet");
		return;
	}

	// Check to see if the destination address matches any addresses
	// in the list of source addresses we've seen on our network.
	// If it is, don't bother sending it over the bridge as the
	// recipient is local.
	struct addrlist *ap;
	struct addrlist *srcaddrmatch = 0;
	for (ap = state->addrHead.tqh_first; ap != NULL; ap = ap->entries.tqe_next) {
		if(memcmp(packet, ap->srcaddr, 6) == 0 ) {
			logDebug("packetHandler returned, skipping local packet");
			return;
		}
		// Since we're going through the list anyway, see if
		// the source address we've observed is already in the
		// list, in case we want to add it.
		if(memcmp(packet + 6, ap->srcaddr, 6) == 0)
			srcaddrmatch = ap;
	}

	// Destination is remote, but originated locally, so we can add
	// the source address to our list.
	if(!srcaddrmatch) {
		char buf[255];
		struct addrlist *newaddr = calloc(1, sizeof(struct addrlist));
		memcpy(newaddr->srcaddr, packet + 6, 6);
		parseMAC(buf, sizeof(buf), newaddr->srcaddr);
		logDebug("Adding local address %s", buf);
		TAILQ_INSERT_TAIL(&state->addrHead, newaddr, entries);
	}

	if(header->caplen != header->len)
		logError("truncated packet!");

	logDebug("relaying packet of size %d", header->caplen);

	if(state->q) {
		amqp_basic_properties_t props;
		props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
		props.content_type = amqp_cstring_bytes("application/x-appletalk-packet");
		props.delivery_mode = 2; /* persistent delivery mode */
		amqp_bytes_t messageBody;
		messageBody.len = header->caplen;
		messageBody.bytes = (void*)packet;
		if(amqp_basic_publish(state->q->conn, 1, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes(getSetting("ClientID")), 0, 0, &props, messageBody) < 0)
			logError("Unable to publish packet");
	}
}

void *capture(void *ctx) {
	CaptureState *state = (CaptureState*)ctx;
	char errBuf[PCAP_ERRBUF_SIZE];
	char *dev = getSetting("Interface");

	logMessage("Capturing device: %s", dev);
	pcapHandle = pcap_open_live(dev, BUFSIZ, 1, 1000, errBuf);
	if(pcapHandle == 0) {
		logError("Couldn't open pcap for device %s: %s", dev, errBuf);
		return 0;
	}

	TAILQ_INIT(&packetHead);

	state->q = queueConnect();
	TAILQ_INIT(&state->addrHead);

	char *filter = "atalk or aarp";
	struct bpf_program fp;
	if(pcap_compile(pcapHandle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		logError("Couldn't parse filter %s: %s", filter, pcap_geterr(pcapHandle));
		return 0;
	}

	if(pcap_setfilter(pcapHandle, &fp) == -1) {
		logError("Couldn't install filter %s: %s", filter, pcap_geterr(pcapHandle));
		return 0;
	}

	pcap_loop(pcapHandle, -1, packetHandler, ctx);
	return 0;
}

bool startPacketCapture() {
	pthread_attr_t defaultattrs;
	pthread_attr_init(&defaultattrs);

	pthread_mutex_init(&captureMutex, 0);

	pcapState = (CaptureState*)malloc(sizeof(CaptureState));
	pcapState->q = 0;

	if(pthread_create(&captureThread, &defaultattrs, capture, pcapState) != 0) {
		pthread_attr_destroy(&defaultattrs);
		logError("Couldn't create capture thread");
		return false;
	}
	pthread_attr_destroy(&defaultattrs);
	return true;
}

void stopPacketCapture() {
	if(pcapHandle == 0)
		return;
	logMessage("Stopping capture");
	pcap_breakloop(pcapHandle);
	pthread_cancel(captureThread);
	pthread_join(captureThread, 0);
	pthread_mutex_destroy(&captureMutex);
	if(pcapState != 0)
		queueDisconnect(pcapState->q);
	free(pcapState);
	pcapState = 0;
	pcap_close(pcapHandle);
	pcapHandle = 0;
}
