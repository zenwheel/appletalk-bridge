#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdbool.h>

// rabbitmq-c 0.12 moved its headers under rabbitmq-c/ and deprecated the old names
#if defined(__has_include) && __has_include(<rabbitmq-c/amqp.h>)
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/framing.h>
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/ssl_socket.h>
#else
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#endif

typedef struct QueueConnection {
	amqp_connection_state_t conn;
	amqp_socket_t *socket;
	amqp_bytes_t queueName;
	bool loggedIn;
	bool channelOpen;
} QueueConnection;

bool checkAMQPStatus(amqp_rpc_reply_t status, char const *context);
QueueConnection *queueConnect(void);
void queueDisconnect(QueueConnection *q);
void queueMarkBroken(QueueConnection *q);
bool queueIsAlive(QueueConnection *q);

#endif
