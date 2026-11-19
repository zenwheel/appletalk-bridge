#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "http.h"
#include "log.h"
#include "settings.h"

#define HTTP_MAX_RESPONSE (8 * 1024 * 1024)

static size_t writeFunc(char *ptr, size_t size, size_t nmemb, void *userdata) {
	HTTPContext *http = userdata;
	size_t chunk = size * nmemb;

	if(chunk > HTTP_MAX_RESPONSE - http->len) {
		http->overflow = true;
		return 0; // abort the transfer
	}

	char *response = realloc(http->response, http->len + chunk + 1);
	if(response == 0)
		return 0;
	http->response = response;
	memcpy(http->response + http->len, ptr, chunk);
	http->len += chunk;
	http->response[http->len] = 0;
	return chunk;
}

HTTPContext *createHTTPContext(void) {
	HTTPContext *http = calloc(1, sizeof(HTTPContext));
	if(http == 0)
		return 0;

	http->curl = curl_easy_init();
	if(http->curl == 0) {
		logError("Can't initialize curl");
		free(http);
		return 0;
	}

	curl_easy_setopt(http->curl, CURLOPT_NOSIGNAL, 1L); // required in multithreaded programs
	curl_easy_setopt(http->curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(http->curl, CURLOPT_TIMEOUT, 10L);
	curl_easy_setopt(http->curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
	curl_easy_setopt(http->curl, CURLOPT_WRITEFUNCTION, writeFunc);
	curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, http);
	curl_easy_setopt(http->curl, CURLOPT_USERAGENT, USER_AGENT);

	// use the same TLS trust settings as the AMQP connection
	if(getSetting("SSLCACertificateFile"))
		curl_easy_setopt(http->curl, CURLOPT_CAINFO, getSetting("SSLCACertificateFile"));
	if(!getBoolSetting("SSLVerifyPeer"))
		curl_easy_setopt(http->curl, CURLOPT_SSL_VERIFYPEER, 0L);
	if(!getBoolSetting("SSLVerifyHostname"))
		curl_easy_setopt(http->curl, CURLOPT_SSL_VERIFYHOST, 0L);

	return http;
}

bool httpGet(HTTPContext *http, const char *url, const char *username, const char *password) {
	if(http == 0)
		return false;

	free(http->response);
	http->response = 0;
	http->len = 0;
	http->overflow = false;

	curl_easy_setopt(http->curl, CURLOPT_USERNAME, username);
	curl_easy_setopt(http->curl, CURLOPT_PASSWORD, password);
	curl_easy_setopt(http->curl, CURLOPT_URL, url);

	CURLcode res = curl_easy_perform(http->curl);
	long code = 0;
	curl_easy_getinfo(http->curl, CURLINFO_RESPONSE_CODE, &code);

	if(res != CURLE_OK || code != 200 || http->response == 0) {
		if(http->overflow)
			logError("HTTP response from %s was too large", url);
		else if(res != CURLE_OK)
			logError("HTTP request failed: %s", curl_easy_strerror(res));
		else
			logError("HTTP request to %s returned status %ld", url, code);
		free(http->response);
		http->response = 0;
		http->len = 0;
		return false;
	}
	return true;
}

void destroyHTTPContext(HTTPContext *http) {
	if(http == 0)
		return;

	if(http->curl)
		curl_easy_cleanup(http->curl);
	free(http->response);
	free(http);
}
