#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <json-c/json.h>
#include "uthash/src/uthash.h"
#include "http.h"
#include "log.h"
#include "settings.h"
#include "urlencode.h"
#include "rmq_api.h"

typedef struct RMQClient {
	char name[255];
	char address[255];
	char user[255];
	char node[255];
	UT_hash_handle hh;
} RMQClient;

RMQClient *clients = 0;

void clearClients() {
	RMQClient *client = 0, *tmp = 0;
	HASH_ITER(hh, clients, client, tmp) {
		HASH_DEL(clients, client);
		free(client);
	}
	clients = 0;
}

void showClients() {
	char buf[1024];
	char *bindings = 0;
	int port = atoi(getSetting("APIPort"));
	char *consumers = 0;
	size_t bindingsLen = 0;
	size_t consumersLen = 0;
	char *vhost = urlEncode(getSetting("VHost"));
	struct json_tokener *tokener = json_tokener_new();

	if(port < 0) {
		free(vhost);
		clearClients();
		return;
	}

	HTTPContext *http = createHTTPContext();
	snprintf(buf, sizeof(buf), "http%s://%s:%d/api/exchanges/%s/%s/bindings/source", strcmp(getSetting("APIUseSSL"), "true") == 0 ? "s" : "", getSetting("Server"), port, vhost, getSetting("AMQPExchange"));
	httpGet(http, buf, getSetting("User"), getSetting("Password"));
	if(http->response) {
		bindings = strdup(http->response);
		bindingsLen = http->len;
	}

	snprintf(buf, sizeof(buf), "http%s://%s:%d/api/consumers/%s", strcmp(getSetting("APIUseSSL"), "true") == 0 ? "s" : "", getSetting("Server"), port, vhost);
	httpGet(http, buf, getSetting("User"), getSetting("Password"));
	if(http->response) {
		consumers = strdup(http->response);
		consumersLen = http->len;
	}

	free(vhost);
	vhost = 0;

	if(bindings && consumers) {
		struct json_object *bindingObj = json_tokener_parse_ex(tokener, bindings, bindingsLen);

		// first find all bindings to our exchange
		if(bindingObj != 0) {
			//logDebug("%s", json_object_to_json_string_ext(bindingObj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
			//logDebug("Binding Count: %d", json_object_array_length(bindingObj));

			for(int i = 0; i < json_object_array_length(bindingObj); i++) {
				struct json_object *item = json_object_array_get_idx(bindingObj, i);
				struct json_object *name;
				if(json_object_object_get_ex(item, "destination", &name)) {
					const char *queueName = json_object_get_string(name);
					//logDebug("binding queue: %s", queueName);
					RMQClient *client = 0;
					HASH_FIND_STR(clients, queueName, client);
					if(client == 0) {
						client = (RMQClient*)malloc(sizeof(RMQClient));
						memset(client, 0, sizeof(RMQClient));
						strncpy(client->name, queueName, sizeof(client->name));
						strncpy(client->address, "--", sizeof(client->address));
						HASH_ADD_STR(clients, name, client);
					}
					json_object_put(name);
				}
				json_object_put(item);
			}

			json_object_put(bindingObj);
		}

		struct json_object *consumerObj = json_tokener_parse_ex(tokener, consumers, consumersLen);
		if(consumerObj != 0) {
			//logDebug("%s", json_object_to_json_string_ext(consumerObj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
			//logDebug("Consumer Count: %d", json_object_array_length(consumerObj));

			for(int i = 0; i < json_object_array_length(consumerObj); i++) {
				struct json_object *item = json_object_array_get_idx(consumerObj, i);
				struct json_object *channelObj = 0;
				struct json_object *peerHostObj = 0;
				struct json_object *userObj = 0;
				struct json_object *nodeObj = 0;
				if(json_object_object_get_ex(item, "channel_details", &channelObj)) {
					if(json_object_object_get_ex(channelObj, "peer_host", &peerHostObj)) {
						//logDebug("consumer peer address: %s", json_object_get_string(peerHostObj));
					}
					json_object_object_get_ex(channelObj, "user", &userObj);
					json_object_object_get_ex(channelObj, "node", &nodeObj);
				}
				struct json_object *queueObj = 0;
				struct json_object *queueNameObj = 0;
				if(json_object_object_get_ex(item, "queue", &queueObj)) {
					if(json_object_object_get_ex(queueObj, "name", &queueNameObj)) {
						//logDebug("consumer queue: %s", json_object_get_string(queueNameObj));
					}
				}

				if(peerHostObj && queueNameObj && nodeObj && userObj) {
					const char *queueName = json_object_get_string(queueNameObj);
					const char *peerHost = json_object_get_string(peerHostObj);
					RMQClient *client = 0;
					HASH_FIND_STR(clients, queueName, client);
					if(client) {
						// client will only be found if it's bound to the proper exchange
						strncpy(client->address, peerHost, sizeof(client->address));
						strncpy(client->user, json_object_get_string(userObj), sizeof(client->user));
						strncpy(client->node, json_object_get_string(nodeObj), sizeof(client->node));
					}
				}

				if(peerHostObj)
					json_object_put(peerHostObj);
				if(userObj)
					json_object_put(userObj);
				if(nodeObj)
					json_object_put(nodeObj);
				if(channelObj)
					json_object_put(channelObj);
				if(queueNameObj)
					json_object_put(queueNameObj);
				if(queueObj)
					json_object_put(queueObj);
				json_object_put(item);
			}

			json_object_put(consumerObj);
		}
	}

	unsigned int clientCount = HASH_COUNT(clients);
	printf("There are %u connected clients: ", clientCount);
	for(RMQClient *client = clients; client; client = client->hh.next) {
		printf("%s%s", client->address, client->hh.next ? ", " : "");
	}
	printf("\n");

	destroyHTTPContext(http);
	json_tokener_free(tokener);

	if(bindings)
		free(bindings);
	if(consumers)
		free(consumers);
	bindings = consumers = 0;
}

