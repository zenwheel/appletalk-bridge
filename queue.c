#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp_framing.h>
#include "client.h"
#include "settings.h"
#include "log.h"
#include "queue.h"

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
					logError("%s: server connection error %uh, message: %.*s", context, m->reply_code, (int)m->reply_text.len, m->reply_text.bytes);
					break;
				}
				case AMQP_CHANNEL_CLOSE_METHOD: {
					amqp_channel_close_t *m = (amqp_channel_close_t*)status.reply.decoded;
					logError("%s: server channel error %uh, message: %.*s", context, m->reply_code, (int)m->reply_text.len, m->reply_text.bytes);
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

QueueConnection *queueConnect() {
	QueueConnection *q = (QueueConnection*)malloc(sizeof(QueueConnection));
	q->conn = amqp_new_connection();
	q->socket = 0;
	q->queueName.bytes = 0;

	logDebug("Connecting to %s:%d...", getSetting("Server"), atoi(getSetting("Port")));

	if(strcmp(getSetting("UseSSL"), "true") == 0) {
		q->socket = amqp_ssl_socket_new(q->conn);

		if(strcmp(getSetting("SSLVerifyPeer"), "true") == 0)
			amqp_ssl_socket_set_verify_peer(q->socket, 1);
		else
			amqp_ssl_socket_set_verify_peer(q->socket, 0);

		if(strcmp(getSetting("SSLVerifyHostname"), "true") == 0)
			amqp_ssl_socket_set_verify_hostname(q->socket, 1);
		else
			amqp_ssl_socket_set_verify_hostname(q->socket, 0);

		if(getSetting("SSLCACertificateFile") != 0) {
			if(amqp_ssl_socket_set_cacert(q->socket, getSetting("SSLCACertificateFile")) < 0) {
				logError("Can't load CA certificate file");
				queueDisconnect(q);
				return 0;
			}
		}
		if(getSetting("SSLClientCertificateFile") != 0 && getSetting("SSLKeyFile") != 0) {
			if(amqp_ssl_socket_set_key(q->socket, getSetting("SSLClientCertificateFile"), getSetting("SSLKeyFile")) < 0) {
				logError("Can't load client certificate and key file");
				queueDisconnect(q);
				return 0;
			}
		}
	} else {
		q->socket = amqp_tcp_socket_new(q->conn);
	}

	if (q->socket == 0) {
		logError("Can't create AMQP socket");
		queueDisconnect(q);
		return 0;
	}

	if(amqp_socket_open(q->socket, getSetting("Server"), atoi(getSetting("Port")))) {
		logError("Unable to open AMQP socket");
		queueDisconnect(q);
		return 0;
	}

	amqp_rpc_reply_t status = amqp_login(q->conn, getSetting("VHost"), 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, getSetting("User"), getSetting("Password"));
	if(checkAMQPStatus(status, "amqp_login") == false) {
		queueDisconnect(q);
		return 0;
	}

	amqp_channel_open(q->conn, 1);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_channel_open") == false) {
		queueDisconnect(q);
		return 0;
	}

	amqp_exchange_declare(q->conn, 1, amqp_cstring_bytes(getSetting("AMQPExchange")), amqp_cstring_bytes("fanout"), 0, 0, 0, 0, amqp_empty_table);
	status = amqp_get_rpc_reply(q->conn);
	if(checkAMQPStatus(status, "amqp_exchange_declare") == false) {
		queueDisconnect(q);
		return 0;
	}

	logDebug("Connected to %s:%d", getSetting("Server"), atoi(getSetting("Port")));
	return q;
}

void queueDisconnect(QueueConnection *q) {
	if(q == 0)
		return;

	if(q->queueName.bytes)
		amqp_bytes_free(q->queueName);

	amqp_rpc_reply_t status = amqp_channel_close(q->conn, 1, AMQP_REPLY_SUCCESS);
	if(checkAMQPStatus(status, "amqp_channel_close")) {
		status = amqp_connection_close(q->conn, AMQP_REPLY_SUCCESS);
		if(checkAMQPStatus(status, "amqp_connection_close")) {
			if(amqp_destroy_connection(q->conn) < 0)
				logError("Unable to destroy connection");
		}
	}

	free(q);
}
