#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include "main.h"
#include "client.h"
#include "settings.h"
#include "ddp.h"
#include "log.h"
#include "queue.h"
#include "pcap.h"

/* adapted from http://www.synack.net/~bbraun/abridge.html */

static void logTotals(uint64_t packetCount, uint64_t totalBytes) {
	static const char *units[] = { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB" };
	size_t unit = 0;
	uint64_t amount = totalBytes;
	while(amount >= 1024 && unit < sizeof(units) / sizeof(units[0]) - 1) {
		amount /= 1024;
		unit++;
	}
	logMessage("Packet count: %" PRIu64 ", %" PRIu64 " %s", packetCount, amount, units[unit]);
}

static bool isOwnRoutingKey(amqp_bytes_t key) {
	const char *clientID = getSetting("ClientID");
	size_t len = strlen(clientID);
	return key.len == len && memcmp(key.bytes, clientID, len) == 0;
}

bool clientConnect(void) {
	bool monitor = getBoolSetting("MonitorMode");
	bool consuming = false;

	QueueConnection *q = queueConnect();
	if(q == 0)
		return false;

	pcap_t *pcapHandle = 0;
	if(!monitor) {
		if((pcapHandle = openInterface(getSetting("Interface"), false)) == 0) {
			queueDisconnect(q);
			return false;
		}
	}

	// server-named, non-durable, exclusive, auto-delete queue just for us
	amqp_queue_declare_ok_t *r = amqp_queue_declare(q->conn, 1, amqp_empty_bytes, 0, 0, 1, 1, amqp_empty_table);
	amqp_rpc_reply_t status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_queue_declare") == false)
		goto done;

	q->queueName = amqp_bytes_malloc_dup(r->queue);
	if (q->queueName.bytes == 0) {
		logError("Out of memory while copying queue name");
		goto done;
	}

	logMessage("Listening for messages on queue: %.*s", (int)q->queueName.len, (char *)q->queueName.bytes);

	amqp_queue_bind(q->conn, 1, q->queueName, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes("*"), amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_queue_bind") == false)
		goto done;

	amqp_basic_consume(q->conn, 1, q->queueName, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_basic_consume") == false)
		goto done;

	consuming = true;
	uint64_t packetCount = 0;
	uint64_t totalBytes = 0;

	while(m_run) {
		amqp_envelope_t envelope;

		amqp_maybe_release_buffers(q->conn);

		struct timeval consume_timeout = { 1, 0 };
		amqp_rpc_reply_t res = amqp_consume_message(q->conn, &envelope, &consume_timeout, 0);

		if(AMQP_RESPONSE_LIBRARY_EXCEPTION == res.reply_type && AMQP_STATUS_TIMEOUT == res.library_error)
			continue;
		if (AMQP_RESPONSE_NORMAL != res.reply_type) {
			checkAMQPStatus(res, "amqp_consume_message");
			queueMarkBroken(q);
			break;
		}

		logDebug("Delivery %" PRIu64 ", exchange %.*s routingkey %.*s", (uint64_t)envelope.delivery_tag, (int)envelope.exchange.len, (char *)envelope.exchange.bytes, (int)envelope.routing_key.len, (char *)envelope.routing_key.bytes);
		packetCount++;
		totalBytes += envelope.message.body.len;
		if(isOwnRoutingKey(envelope.routing_key)) {
			logDebug("Skipping captured packet from queue");
			amqp_destroy_envelope(&envelope);
			continue;
		}

		const uint8_t *body = envelope.message.body.bytes;
		size_t bodyLen = envelope.message.body.len;
		logDebug("Length: %zu", bodyLen);

		if(!monitor) {
			// Anyone who can publish to the exchange controls these bytes, so
			// never put anything but a well-formed AppleTalk frame on the wire.
			if(!isAppleTalkFrame(body, bodyLen)) {
				logError("Dropping non-AppleTalk frame (%zu bytes) from the queue", bodyLen);
			} else {
				rememberRemoteSource(body, bodyLen);
				if(pcap_sendpacket(pcapHandle, body, (int)bodyLen) != 0)
					logError("Error sending packet out onto local network: %s", pcap_geterr(pcapHandle));
			}
		} else {
			DDPPacketInfo *pkt = ddpParsePacket(body, bodyLen);
			printPacketInfo(pkt);
			freePacketInfo(pkt);
			logTotals(packetCount, totalBytes);
		}

		amqp_destroy_envelope(&envelope);
	}

done:
	if(pcapHandle != 0)
		pcap_close(pcapHandle);

	queueDisconnect(q);
	return consuming;
}
