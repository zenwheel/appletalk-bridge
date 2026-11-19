#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <syslog.h>
#include "log.h"
#include "settings.h"

// When running in the foreground messages go to the terminal; once
// daemonized (InForeground = false) they go to syslog instead.

static void logv(int priority, FILE *out, const char *format, va_list args) {
	if(getBoolSetting("InForeground")) {
		vfprintf(out, format, args);
		fputc('\n', out);
		fflush(out);
	} else {
		vsyslog(priority, format, args);
	}
}

void logDebug(const char *format, ...) {
#if DEBUG
	va_list args;
	va_start(args, format);
	logv(LOG_DEBUG, stdout, format, args);
	va_end(args);
#else
	(void)format;
#endif
}

void logMessage(const char *format, ...) {
	va_list args;
	va_start(args, format);
	logv(LOG_INFO, stdout, format, args);
	va_end(args);
}

void logError(const char *format, ...) {
	va_list args;
	va_start(args, format);
	logv(LOG_ERR, stderr, format, args);
	va_end(args);
}
