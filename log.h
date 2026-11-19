#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>

#define LOG_PRINTF __attribute__((format(printf, 1, 2)))

void logDebug(const char *format, ...) LOG_PRINTF;
void logMessage(const char *format, ...) LOG_PRINTF;
void logError(const char *format, ...) LOG_PRINTF;

#endif
