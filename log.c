#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include "settings.h"

void logDebug(char *format, ...) {
	if(strcmp(getSetting("InForeground"), "false") == 0) return;
#if DEBUG
	char buf[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	printf("%s\n", buf);
	va_end(args);
#endif
}

void logMessage(char *format, ...) {
	char buf[1024];
	if(strcmp(getSetting("InForeground"), "false") == 0) return;
	va_list args;
	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	printf("%s\n", buf);
	va_end(args);
}

void logError(char *format, ...) {
	char buf[1024];
	if(strcmp(getSetting("InForeground"), "false") == 0) return;
	va_list args;
	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	fprintf(stderr, "%s\n", buf);
	va_end(args);
}
