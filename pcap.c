#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>
#include "main.h"
#include "pcap.h"
#include "ddp.h"
#include "log.h"
#include "settings.h"
#include "queue.h"

/* adapted from http://www.synack.net/~bbraun/abridge.html */

#define CAPTURE_SNAPLEN 2048        // > max Ethernet frame (macOS BUFSIZ is only 1024)
#define CAPTURE_TIMEOUT_MS 250      // how often a blocked read wakes to notice shutdown
#define MAX_REMOTE_ADDRESSES 1024   // MACs learned from frames that arrived over the bridge
#define REMOTE_ADDRESS_TTL 600      // seconds before a quiet remote MAC is forgotten
#define MAX_LOCAL_ADDRESSES 1024    // local MACs remembered to avoid relaying local traffic
#define PUBLISH_RECONNECT_SECONDS 5

struct addrlist {
	uint8_t srcaddr[6];
	TAILQ_ENTRY(addrlist) entries;
};

typedef struct CaptureState {
	QueueConnection *q;
	time_t lastConnectAttempt;
	TAILQ_HEAD(addrq, addrlist) addrHead;
	size_t addrCount;
} CaptureState;

// Source MACs of frames we injected. Like a learning bridge, a captured frame
// whose source lives on the far side is never relayed back; this breaks loops
// even when the network hands us extra copies of what we sent.
static struct { uint8_t mac[6]; time_t seen; } remoteAddrs[MAX_REMOTE_ADDRESSES];
static size_t remoteCount = 0;
static pthread_mutex_t remoteMutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t captureThread;
static bool captureRunning = false;
static pcap_t *pcapHandle = 0;
static CaptureState *pcapState = 0;

void printBuffer(const uint8_t *buffer, size_t len) {
	for(size_t i = 0; i < len; i++)
		printf("%02x", buffer[i]);
	printf("\n");
}

pcap_t *openInterface(const char *dev, bool forCapture) {
	char errBuf[PCAP_ERRBUF_SIZE];

	if(dev == 0) {
		logError("No network interface specified");
		return 0;
	}

	pcap_t *handle = pcap_create(dev, errBuf);
	if(handle == 0) {
		logError("Couldn't open pcap for device %s: %s", dev, errBuf);
		return 0;
	}

	pcap_set_snaplen(handle, forCapture ? CAPTURE_SNAPLEN : 64);
	pcap_set_promisc(handle, forCapture ? 1 : 0);
	pcap_set_timeout(handle, CAPTURE_TIMEOUT_MS);
	// deliver each frame as it arrives instead of batching for up to the timeout
	if(forCapture)
		pcap_set_immediate_mode(handle, 1);

	int rc = pcap_activate(handle);
	if(rc < 0) {
		logError("Couldn't open pcap for device %s: %s%s", dev, pcap_geterr(handle),
			geteuid() != 0 ? " (packet capture needs root, or CAP_NET_RAW on Linux)" : "");
		pcap_close(handle);
		return 0;
	}
	if(rc > 0)
		logError("Warning opening %s: %s", dev, pcap_statustostr(rc));

	if(pcap_datalink(handle) != DLT_EN10MB) {
		logError("%s is not an Ethernet interface", dev);
		pcap_close(handle);
		return 0;
	}

	return handle;
}

void rememberRemoteSource(const uint8_t *frame, size_t len) {
	if(len < 12)
		return;
	const uint8_t *mac = frame + 6;
	time_t now = time(0);

	pthread_mutex_lock(&remoteMutex);
	size_t slot = remoteCount, oldest = 0;
	for(size_t i = 0; i < remoteCount; i++) {
		if(memcmp(remoteAddrs[i].mac, mac, 6) == 0) {
			slot = i;
			break;
		}
		if(remoteAddrs[i].seen < remoteAddrs[oldest].seen)
			oldest = i;
	}
	if(slot == remoteCount) {
		if(remoteCount < MAX_REMOTE_ADDRESSES)
			remoteCount++;
		else
			slot = oldest; // table full: recycle the least recently seen entry
		memcpy(remoteAddrs[slot].mac, mac, 6);
	}
	remoteAddrs[slot].seen = now;
	pthread_mutex_unlock(&remoteMutex);
}

static bool isFromRemote(const uint8_t *frame) {
	bool found = false;
	time_t now = time(0);

	pthread_mutex_lock(&remoteMutex);
	for(size_t i = 0; i < remoteCount; i++) {
		if(memcmp(remoteAddrs[i].mac, frame + 6, 6) == 0) {
			found = now - remoteAddrs[i].seen < REMOTE_ADDRESS_TTL;
			break;
		}
	}
	pthread_mutex_unlock(&remoteMutex);
	return found;
}

static void publishPacket(CaptureState *state, const uint8_t *bytes, size_t len) {
	if(state->q != 0 && !queueIsAlive(state->q)) {
		queueDisconnect(state->q);
		state->q = 0;
		state->lastConnectAttempt = 0; // try again right away
	}

	if(state->q == 0) {
		time_t now = time(0);
		if(now - state->lastConnectAttempt < PUBLISH_RECONNECT_SECONDS)
			return; // drop the packet until we can reconnect
		state->lastConnectAttempt = now;
		if((state->q = queueConnect()) == 0)
			return;
		logMessage("Publisher connected");
	}

	amqp_basic_properties_t props;
	memset(&props, 0, sizeof(props));
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
	props.content_type = amqp_cstring_bytes("application/x-appletalk-packet");
	props.delivery_mode = 1; // transient: stale packets are worthless, don't write them to disk

	amqp_bytes_t messageBody = { len, (void *)bytes };
	int rc = amqp_basic_publish(state->q->conn, 1, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes(getSetting("ClientID")), 0, 0, &props, messageBody);
	if(rc != AMQP_STATUS_OK) {
		logError("Unable to publish packet: %s; reconnecting", amqp_error_string2(rc));
		queueMarkBroken(state->q);
		queueDisconnect(state->q);
		state->q = 0;
	}
}

static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	CaptureState *state = (CaptureState*)args;

	if(!m_run) {
		pcap_breakloop(pcapHandle);
		return;
	}

	if(header->caplen != header->len) {
		logError("Skipping truncated packet (%u of %u bytes)", header->caplen, header->len);
		return;
	}

	// the BPF filter should guarantee this, but only ever relay well-formed AppleTalk
	if(!isAppleTalkFrame(packet, header->caplen)) {
		logDebug("packetHandler returned, skipping invalid packet");
		return;
	}

	if(isFromRemote(packet)) {
		logDebug("packetHandler returned, skipping packet from a remote network");
		return;
	}

	// Check to see if the destination address matches any addresses
	// in the list of source addresses we've seen on our network.
	// If it is, don't bother sending it over the bridge as the
	// recipient is local.
	struct addrlist *ap;
	struct addrlist *srcaddrmatch = 0;
	TAILQ_FOREACH(ap, &state->addrHead, entries) {
		if(memcmp(packet, ap->srcaddr, 6) == 0) {
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
	if(!srcaddrmatch && state->addrCount < MAX_LOCAL_ADDRESSES) {
		struct addrlist *newaddr = calloc(1, sizeof(struct addrlist));
		if(newaddr) {
			char buf[18];
			memcpy(newaddr->srcaddr, packet + 6, 6);
			parseMAC(buf, sizeof(buf), newaddr->srcaddr);
			logDebug("Adding local address %s", buf);
			TAILQ_INSERT_TAIL(&state->addrHead, newaddr, entries);
			state->addrCount++;
		}
	}

	logDebug("relaying packet of size %u", header->caplen);
	publishPacket(state, packet, header->caplen);
}

static void *capture(void *ctx) {
	CaptureState *state = (CaptureState*)ctx;

	state->lastConnectAttempt = time(0);
	state->q = queueConnect();

	int rc = pcap_loop(pcapHandle, -1, packetHandler, (u_char *)state);
	if(rc == PCAP_ERROR) {
		logError("Packet capture failed: %s", pcap_geterr(pcapHandle));
		m_run = 0; // without capture the bridge is useless, so shut down
	}
	return 0;
}

bool startPacketCapture(void) {
	const char *dev = getSetting("Interface");

	logMessage("Capturing device: %s", dev ? dev : "(none)");
	if((pcapHandle = openInterface(dev, true)) == 0)
		return false;

	const char *filter = "atalk or aarp";
	struct bpf_program fp;
	if(pcap_compile(pcapHandle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
		logError("Couldn't parse filter %s: %s", filter, pcap_geterr(pcapHandle));
		goto fail;
	}
	int rc = pcap_setfilter(pcapHandle, &fp);
	pcap_freecode(&fp);
	if(rc == -1) {
		logError("Couldn't install filter %s: %s", filter, pcap_geterr(pcapHandle));
		goto fail;
	}

	if((pcapState = calloc(1, sizeof(CaptureState))) == 0)
		goto fail;
	TAILQ_INIT(&pcapState->addrHead);

	if(pthread_create(&captureThread, 0, capture, pcapState) != 0) {
		logError("Couldn't create capture thread");
		goto fail;
	}
	captureRunning = true;
	return true;

fail:
	free(pcapState);
	pcapState = 0;
	pcap_close(pcapHandle);
	pcapHandle = 0;
	return false;
}

void stopPacketCapture(void) {
	if(!captureRunning)
		return;
	logMessage("Stopping capture");
	pcap_breakloop(pcapHandle);
	pthread_join(captureThread, 0);
	captureRunning = false;

	queueDisconnect(pcapState->q);
	struct addrlist *ap;
	while((ap = TAILQ_FIRST(&pcapState->addrHead)) != 0) {
		TAILQ_REMOVE(&pcapState->addrHead, ap, entries);
		free(ap);
	}
	free(pcapState);
	pcapState = 0;

	pthread_mutex_lock(&remoteMutex);
	remoteCount = 0;
	pthread_mutex_unlock(&remoteMutex);

	pcap_close(pcapHandle);
	pcapHandle = 0;
}
