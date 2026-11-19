#include <stdlib.h>
#include <string.h>
#include "urlencode.h"

/* Returns a percent-encoded copy of str suitable for a URL path segment
 * (RFC 3986 unreserved characters are left alone).
 * IMPORTANT: be sure to free() the returned string after use */
char *urlEncode(const char *str) {
	static const char hex[] = "0123456789ABCDEF";

	if(str == 0)
		str = "";
	char *buf = malloc(strlen(str) * 3 + 1);
	if(buf == 0)
		return 0;

	char *pbuf = buf;
	for(const unsigned char *p = (const unsigned char *)str; *p; p++) {
		if((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
				*p == '-' || *p == '_' || *p == '.' || *p == '~') {
			*pbuf++ = *p;
		} else {
			*pbuf++ = '%';
			*pbuf++ = hex[*p >> 4];
			*pbuf++ = hex[*p & 15];
		}
	}
	*pbuf = 0;
	return buf;
}
