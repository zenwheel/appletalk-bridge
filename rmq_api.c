#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <uthash.h>
#include "http.h"
#include "log.h"
#include "settings.h"
#include "urlencode.h"
#include "rmq_api.h"

typedef struct RMQClient {
	char name[256];
	char address[256];
	char user[256];
	char node[256];
	UT_hash_handle hh;
} RMQClient;

static RMQClient *clients = 0;

static void clearClients(void) {
	RMQClient *client = 0, *tmp = 0;
	HASH_ITER(hh, clients, client, tmp) {
		HASH_DEL(clients, client);
		free(client);
	}
	clients = 0;
}

// Fetch url and parse it as a JSON array. The caller owns the result.
static struct json_object *fetchArray(HTTPContext *http, const char *url) {
	if(!httpGet(http, url, getSetting("User"), getSetting("Password")))
		return 0;

	struct json_object *obj = json_tokener_parse(http->response);
	if(obj == 0 || !json_object_is_type(obj, json_type_array)) {
		logError("Unexpected response from %s", url);
		json_object_put(obj);
		return 0;
	}
	return obj;
}

// json-c getters return borrowed references: never json_object_put() them
static const char *getString(struct json_object *obj, const char *key) {
	struct json_object *value = 0;
	if(obj == 0 || !json_object_object_get_ex(obj, key, &value) || !json_object_is_type(value, json_type_string))
		return 0;
	return json_object_get_string(value);
}

static struct json_object *getObject(struct json_object *obj, const char *key) {
	struct json_object *value = 0;
	if(obj == 0 || !json_object_object_get_ex(obj, key, &value) || !json_object_is_type(value, json_type_object))
		return 0;
	return value;
}

void showClients(void) {
	int port = atoi(getSetting("APIPort"));
	if(port <= 0)
		return;

	const char *scheme = getBoolSetting("APIUseSSL") ? "https" : "http";
	char *vhost = urlEncode(getSetting("VHost"));
	char *exchange = urlEncode(getSetting("AMQPExchange"));
	HTTPContext *http = createHTTPContext();
	struct json_object *bindings = 0, *consumers = 0;
	char url[1024];

	if(vhost == 0 || exchange == 0 || http == 0)
		goto done;

	// rebuild the list every time so clients that went away disappear
	clearClients();

	// first find all queues bound to our exchange
	snprintf(url, sizeof(url), "%s://%s:%d/api/exchanges/%s/%s/bindings/source", scheme, getSetting("Server"), port, vhost, exchange);
	if((bindings = fetchArray(http, url)) == 0)
		goto done;

	size_t count = json_object_array_length(bindings);
	for(size_t i = 0; i < count; i++) {
		const char *queueName = getString(json_object_array_get_idx(bindings, i), "destination");
		if(queueName == 0)
			continue;

		RMQClient *client = 0;
		HASH_FIND_STR(clients, queueName, client);
		if(client == 0) {
			if((client = calloc(1, sizeof(RMQClient))) == 0)
				break;
			snprintf(client->name, sizeof(client->name), "%s", queueName);
			snprintf(client->address, sizeof(client->address), "--");
			HASH_ADD_STR(clients, name, client);
		}
	}

	// then fill in where each consumer of those queues is connecting from
	snprintf(url, sizeof(url), "%s://%s:%d/api/consumers/%s", scheme, getSetting("Server"), port, vhost);
	if((consumers = fetchArray(http, url)) == 0)
		goto done;

	count = json_object_array_length(consumers);
	for(size_t i = 0; i < count; i++) {
		struct json_object *item = json_object_array_get_idx(consumers, i);
		struct json_object *channel = getObject(item, "channel_details");
		const char *queueName = getString(getObject(item, "queue"), "name");
		const char *peerHost = getString(channel, "peer_host");
		const char *user = getString(channel, "user");
		const char *node = getString(channel, "node");

		if(queueName == 0 || peerHost == 0)
			continue;

		RMQClient *client = 0;
		HASH_FIND_STR(clients, queueName, client);
		if(client) {
			// client will only be found if it's bound to the proper exchange
			snprintf(client->address, sizeof(client->address), "%s", peerHost);
			snprintf(client->user, sizeof(client->user), "%s", user ? user : "");
			snprintf(client->node, sizeof(client->node), "%s", node ? node : "");
		}
	}

	logMessage("There are %u connected clients:", HASH_COUNT(clients));
	for(RMQClient *client = clients; client; client = client->hh.next)
		logMessage("  %s (%s)", client->address, client->user[0] ? client->user : "?");

done:
	json_object_put(bindings);
	json_object_put(consumers);
	destroyHTTPContext(http);
	free(vhost);
	free(exchange);
}
