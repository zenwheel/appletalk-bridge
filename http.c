#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "http.h"
#include "log.h"

size_t writeFunc(void *ptr, size_t size, size_t nmemb, HTTPContext *http) {
	size_t len = http->len + size * nmemb;
	http->response = realloc(http->response, len + 1);
	memcpy(http->response + http->len, ptr, size * nmemb);
	http->response[len] = 0;
	http->len = len;
	return size * nmemb;
}

HTTPContext *createHTTPContext() {
	HTTPContext *http = (HTTPContext*)malloc(sizeof(HTTPContext));

	http->curl = curl_easy_init();
	if(http->curl == 0) {
		logError("Can't initialize curl");
		free(http);
		return 0;
	}

	http->len = 0;
	http->response = malloc(http->len + 1);
	http->response[0] = 0;

#if DEBUG
	curl_easy_setopt(http->curl, CURLOPT_VERBOSE, 0);
#else
	curl_easy_setopt(http->curl, CURLOPT_VERBOSE, 0);
#endif
	curl_easy_setopt(http->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(http->curl, CURLOPT_WRITEFUNCTION, writeFunc);
	curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, http);
	curl_easy_setopt(http->curl, CURLOPT_USERAGENT, USER_AGENT);

	return http;
}

void httpGet(HTTPContext *http, char *url, char *username, char *password) {
	if(http == 0)
		return;

	if(http->response)
		free(http->response);
	http->response = 0;

	http->len = 0;
	http->response = malloc(http->len + 1);
	http->response[0] = 0;

	curl_easy_setopt(http->curl, CURLOPT_USERNAME, username);
	curl_easy_setopt(http->curl, CURLOPT_PASSWORD, password);
	curl_easy_setopt(http->curl, CURLOPT_URL, url);

	CURLcode res = curl_easy_perform(http->curl);
	if(res != CURLE_OK) {
		logError("curl_easy_perform() failed: %s", curl_easy_strerror(res));
		if(http->response)
			free(http->response);
		http->response = 0;
	}
}

void destroyHTTPContext(HTTPContext *http) {
	if(http == 0)
		return;

	if(http->curl)
		curl_easy_cleanup(http->curl);
	http->curl = 0;

	if(http->response)
		free(http->response);
	http->response = 0;

	free(http);
}

