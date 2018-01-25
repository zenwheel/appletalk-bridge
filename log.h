#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>

void logDebug(char *format, ...);
void logMessage(char *format, ...);
void logError(char *format, ...);

#endif
