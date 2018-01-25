#ifndef __HTTP_H__
#define __HTTP_H__

#include <curl/curl.h>

typedef struct HTTPContext {
	CURL *curl;
	char *response;
	size_t len;
} HTTPContext;

HTTPContext *createHTTPContext();
void httpGet(HTTPContext *http, char *url, char *username, char *password);
void destroyHTTPContext(HTTPContext *http);

#endif
