#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdbool.h>
#include <amqp.h>

typedef struct QueueConnection {
	amqp_connection_state_t conn;
	amqp_socket_t *socket;
	amqp_bytes_t queueName;
} QueueConnection;

bool checkAMQPStatus(amqp_rpc_reply_t status, char const *context);
QueueConnection *queueConnect();
void queueDisconnect(QueueConnection *q);

#endif
