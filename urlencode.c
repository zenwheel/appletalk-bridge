#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* courtesy of http://www.geekhideout.com/urlcode.shtml */
/* Converts an integer value to its hex character*/
char toHex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *urlEncode(char *str) {
	char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
			*pbuf++ = *pstr;
		else if (*pstr == ' ')
			*pbuf++ = '+';
		else
			*pbuf++ = '%', *pbuf++ = toHex(*pstr >> 4), *pbuf++ = toHex(*pstr & 15);
		pstr++;
	}
	*pbuf = 0;
	return buf;
}
