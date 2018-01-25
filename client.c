#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/queue.h>
#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp_framing.h>
#include "client.h"
#include "settings.h"
#include "ddp.h"
#include "log.h"
#include "queue.h"
#include "pcap.h"

/* adapted from http://www.synack.net/~bbraun/abridge.html */

extern bool m_run;
extern TAILQ_HEAD(lastq, packet) packetHead;
extern pthread_mutex_t captureMutex;

void clientConnect() {
	QueueConnection *q = queueConnect();
	if(q == 0)
		return;

	pcap_t *pcapHandle = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(strcmp(getSetting("MonitorMode"), "false") == 0) {
		pcapHandle = pcap_open_live(getSetting("Interface"), 1, 0, 1000, errbuf);
		if(pcapHandle == 0) {
			logError("Couldn't open pcap for device %s: %s", getSetting("Interface"), errbuf);
			queueDisconnect(q);
			return;
		}
	}

	amqp_queue_declare_ok_t *r = amqp_queue_declare(q->conn, 1, amqp_empty_bytes, 0, 0, 0, 1, amqp_empty_table);
	amqp_rpc_reply_t status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_queue_declare") == false) {
		queueDisconnect(q);
		return;
	}

	q->queueName = amqp_bytes_malloc_dup(r->queue);
	if (q->queueName.bytes == 0) {
		logError("Out of memory while copying queue name");
		queueDisconnect(q);
		return;
	}

	logMessage("Listening for messages on queue: %.*s", (int)q->queueName.len, q->queueName.bytes);

	amqp_queue_bind(q->conn, 1, q->queueName, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes("*"), amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_queue_bind") == false) {
		queueDisconnect(q);
		return;
	}

	amqp_basic_consume(q->conn, 1, q->queueName, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_basic_consume") == false) {
		queueDisconnect(q);
		return;
	}

	size_t packetCount = 0;
	size_t totalBytes = 0;

	while(m_run) {
		amqp_rpc_reply_t res;
		amqp_envelope_t envelope;

		amqp_maybe_release_buffers(q->conn);

		struct timeval consume_timeout;
		consume_timeout.tv_sec = 1;
		consume_timeout.tv_usec = 0;

		res = amqp_consume_message(q->conn, &envelope, &consume_timeout, 0);

		if(AMQP_RESPONSE_LIBRARY_EXCEPTION == res.reply_type && AMQP_STATUS_TIMEOUT == res.library_error)
			continue;
		if (AMQP_RESPONSE_NORMAL != res.reply_type)
			break;

		logDebug("Delivery %llu, exchange %.*s routingkey %.*s", envelope.delivery_tag, (int)envelope.exchange.len, envelope.exchange.bytes, (int)envelope.routing_key.len, envelope.routing_key.bytes);
		packetCount++;
		totalBytes += envelope.message.body.len;
		if(strncmp(getSetting("ClientID"), envelope.routing_key.bytes, envelope.routing_key.len) == 0) {
			logDebug("Skipping captured packet from queue");
			amqp_destroy_envelope(&envelope);
			continue;
		}

		if (envelope.message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG)
			logDebug("Content-type: %.*s", (int)envelope.message.properties.content_type.len, envelope.message.properties.content_type.bytes);
		if (envelope.message.properties._flags & AMQP_BASIC_MESSAGE_ID_FLAG)
			logDebug("Message-Id: %.*s", (int)envelope.message.properties.message_id.len, envelope.message.properties.message_id.bytes);

		//logMessage("Body: %.*s", (int)envelope.message.body.len, envelope.message.body.bytes);
		logDebug("Length: %ld", envelope.message.body.len);

		if(strcmp(getSetting("MonitorMode"), "false") == 0 && pcapHandle != 0) {
			struct packet *lastsent = calloc(1, sizeof(struct packet));
			lastsent->len = envelope.message.body.len;
			lastsent->bytes = (uint8_t*)malloc(lastsent->len);
			memcpy(lastsent->bytes, envelope.message.body.bytes, lastsent->len);

			pthread_mutex_lock(&captureMutex);
			TAILQ_INSERT_TAIL(&packetHead, lastsent, entries);
			pthread_mutex_unlock(&captureMutex);
			int pret = pcap_sendpacket(pcapHandle, envelope.message.body.bytes, envelope.message.body.len);
			if(pret != 0)
				logError("Error sending packet out onto local network");
		} else {
			DDPPacketInfo *pkt = ddpParsePacket((uint8_t*)envelope.message.body.bytes, envelope.message.body.len);
			//printPacketDetails(pkt);
			printPacketInfo(pkt);
			freePacketInfo(pkt);

			if(totalBytes > 1125899906842624)
				logMessage("Packet count: %llu, %llu PiB", packetCount, totalBytes / 1125899906842624);
			else if(totalBytes > 1099511627776)
				logMessage("Packet count: %llu, %llu TiB", packetCount, totalBytes / 1099511627776);
			else if(totalBytes > 1073741824)
				logMessage("Packet count: %llu, %llu GiB", packetCount, totalBytes / 1073741824);
			else if(totalBytes > 1048576)
				logMessage("Packet count: %llu, %llu MiB", packetCount, totalBytes / 1048576);
			else if(totalBytes > 1024)
				logMessage("Packet count: %llu, %llu KiB", packetCount, totalBytes / 1024);
			else
				logMessage("Packet count: %llu, %llu bytes", packetCount, totalBytes);
		}

		amqp_destroy_envelope(&envelope);
	}

	if(pcapHandle != 0)
		pcap_close(pcapHandle);
	pcapHandle = 0;

	queueDisconnect(q);
	logMessage("Done.");
}
