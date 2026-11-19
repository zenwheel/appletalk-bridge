#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdbool.h>
#include <curl/curl.h>

typedef struct HTTPContext {
	CURL *curl;
	char *response;
	size_t len;
	bool overflow;
} HTTPContext;

HTTPContext *createHTTPContext(void);
bool httpGet(HTTPContext *http, const char *url, const char *username, const char *password);
void destroyHTTPContext(HTTPContext *http);

#endif
