#ifndef __PATH_H__
#define __PATH_H__

#include <stdbool.h>

bool fileExists(char *path);
char *getFilename(char *path);
void getExePath(char *arg, char *buf, size_t bufLen);
void getDefaultPath(char *arg, char *buf, size_t bufLen);

#endif