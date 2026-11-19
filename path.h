#ifndef __PATH_H__
#define __PATH_H__

#include <stdbool.h>
#include <stddef.h>

bool fileExists(const char *path);
char *getFilename(char *path);
void getExePath(const char *arg, char *buf, size_t bufLen);
void getDefaultPath(const char *arg, char *buf, size_t bufLen);

#endif
