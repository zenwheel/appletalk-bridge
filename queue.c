#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include "settings.h"
#include "log.h"
#include "queue.h"

#define AMQP_CONNECT_TIMEOUT 10 // seconds
#define AMQP_RPC_TIMEOUT 10     // seconds; no broker call may block forever
#define AMQP_FRAME_MAX 131072

bool checkAMQPStatus(amqp_rpc_reply_t status, char const *context) {
	switch (status.reply_type) {
		case AMQP_RESPONSE_NORMAL:
			return true;

		case AMQP_RESPONSE_NONE:
			logError("%s: missing RPC reply type", context);
			break;

		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
			logError("%s: %s", context, amqp_error_string2(status.library_error));
			break;

		case AMQP_RESPONSE_SERVER_EXCEPTION:
			switch (status.reply.id) {
				case AMQP_CONNECTION_CLOSE_METHOD: {
					amqp_connection_close_t *m = (amqp_connection_close_t*)status.reply.decoded;
					logError("%s: server connection error %u, message: %.*s", context, m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
					break;
				}
				case AMQP_CHANNEL_CLOSE_METHOD: {
					amqp_channel_close_t *m = (amqp_channel_close_t*)status.reply.decoded;
					logError("%s: server channel error %u, message: %.*s", context, m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
					break;
				}
				default:
					logError("%s: unknown server error, method id 0x%08X", context, status.reply.id);
					break;
			}
			break;
	}
	return false;
}

static bool configureSSL(QueueConnection *q) {
	bool verifyPeer = getBoolSetting("SSLVerifyPeer");
	amqp_ssl_socket_set_verify_peer(q->socket, verifyPeer);
	amqp_ssl_socket_set_verify_hostname(q->socket, getBoolSetting("SSLVerifyHostname"));
	if(!verifyPeer)
		logError("Warning: SSLVerifyPeer is off; the server's identity is not checked and your credentials could be intercepted");

	const char *caFile = getSetting("SSLCACertificateFile");
	if(caFile != 0) {
		if(amqp_ssl_socket_set_cacert(q->socket, caFile) != AMQP_STATUS_OK) {
			logError("Can't load CA certificate file %s", caFile);
			return false;
		}
	} else if(verifyPeer) {
#if AMQP_VERSION_MAJOR > 0 || AMQP_VERSION_MINOR >= 14
		if(amqp_ssl_socket_enable_default_verify_paths(q->socket) != AMQP_STATUS_OK)
			logError("Warning: couldn't load the system CA certificates");
#else
		logError("Warning: this rabbitmq-c can't use the system CA certificates; set SSLCACertificateFile");
#endif
	}

	const char *certFile = getSetting("SSLClientCertificateFile");
	const char *keyFile = getSetting("SSLKeyFile");
	if(certFile != 0 && keyFile != 0) {
		if(amqp_ssl_socket_set_key(q->socket, certFile, keyFile) != AMQP_STATUS_OK) {
			logError("Can't load client certificate and key file");
			return false;
		}
	}
	return true;
}

QueueConnection *queueConnect(void) {
	QueueConnection *q = calloc(1, sizeof(QueueConnection));
	if(q == 0) {
		logError("Out of memory allocating AMQP connection");
		return 0;
	}
	q->conn = amqp_new_connection();
	if(q->conn == 0) {
		logError("Can't allocate AMQP connection");
		free(q);
		return 0;
	}

	const char *server = getSetting("Server");
	int port = atoi(getSetting("Port"));
	logDebug("Connecting to %s:%d...", server, port);

	if(getBoolSetting("UseSSL")) {
		q->socket = amqp_ssl_socket_new(q->conn);
		if(q->socket != 0 && !configureSSL(q)) {
			queueDisconnect(q);
			return 0;
		}
	} else {
		q->socket = amqp_tcp_socket_new(q->conn);
	}

	if (q->socket == 0) {
		logError("Can't create AMQP socket");
		queueDisconnect(q);
		return 0;
	}

	struct timeval timeout = { AMQP_CONNECT_TIMEOUT, 0 };
	int rc = amqp_socket_open_noblock(q->socket, server, port, &timeout);
	if(rc != AMQP_STATUS_OK) {
		logError("Unable to connect to %s:%d: %s", server, port, amqp_error_string2(rc));
		queueDisconnect(q);
		return 0;
	}

	struct timeval rpcTimeout = { AMQP_RPC_TIMEOUT, 0 };
	amqp_set_rpc_timeout(q->conn, &rpcTimeout);

	amqp_rpc_reply_t status = amqp_login(q->conn, getSetting("VHost"), 0, AMQP_FRAME_MAX, 0, AMQP_SASL_METHOD_PLAIN, getSetting("User"), getSetting("Password"));
	if(checkAMQPStatus(status, "amqp_login") == false) {
		queueDisconnect(q);
		return 0;
	}
	q->loggedIn = true;

	amqp_channel_open(q->conn, 1);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_channel_open") == false) {
		queueDisconnect(q);
		return 0;
	}
	q->channelOpen = true;

	amqp_exchange_declare(q->conn, 1, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes("fanout"), 0, 0, 0, 0, amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_exchange_declare") == false) {
		queueDisconnect(q);
		return 0;
	}

	logDebug("Connected to %s:%d", server, port);
	return q;
}

void queueMarkBroken(QueueConnection *q) {
	if(q == 0)
		return;
	// the server already closed (or the socket died): a polite close would just wait
	q->channelOpen = false;
	q->loggedIn = false;
}

bool queueIsAlive(QueueConnection *q) {
	if(q == 0)
		return false;

	// a publisher never reads, so look for a pending connection.close/channel.close
	amqp_frame_t frame;
	struct timeval zero = { 0, 0 };
	int rc = amqp_simple_wait_frame_noblock(q->conn, &frame, &zero);
	if(rc == AMQP_STATUS_TIMEOUT)
		return true;
	if(rc == AMQP_STATUS_OK && frame.frame_type == AMQP_FRAME_METHOD) {
		if(frame.payload.method.id == AMQP_CONNECTION_CLOSE_METHOD) {
			amqp_connection_close_ok_t ok = { 0 };
			amqp_send_method(q->conn, 0, AMQP_CONNECTION_CLOSE_OK_METHOD, &ok);
		} else if(frame.payload.method.id == AMQP_CHANNEL_CLOSE_METHOD) {
			amqp_channel_close_ok_t ok = { 0 };
			amqp_send_method(q->conn, frame.channel, AMQP_CHANNEL_CLOSE_OK_METHOD, &ok);
		} else {
			return true; // something harmless; ignore it
		}
		logError("Server closed the connection");
	} else if(rc != AMQP_STATUS_OK) {
		logError("AMQP connection error: %s", amqp_error_string2(rc));
	} else {
		return true;
	}
	queueMarkBroken(q);
	return false;
}

void queueDisconnect(QueueConnection *q) {
	if(q == 0)
		return;

	if(q->queueName.bytes)
		amqp_bytes_free(q->queueName);

	// Close politely when we can, but always release the connection: a dead
	// socket makes the close calls fail and used to leak everything.
	if(q->channelOpen)
		amqp_channel_close(q->conn, 1, AMQP_REPLY_SUCCESS);
	if(q->loggedIn)
		amqp_connection_close(q->conn, AMQP_REPLY_SUCCESS);
	if(amqp_destroy_connection(q->conn) < 0)
		logError("Unable to destroy connection");

	free(q);
}
