#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include "path.h"

bool fileExists(const char *path) {
	struct stat statbuf;

	if(path == 0) return false;
	return stat(path, &statbuf) == 0;
}

char *getFilename(char *path) {
	if(path == 0) return 0;
	char *filename = strrchr(path, '/');
	return filename ? filename + 1 : path;
}

void getExePath(const char *arg, char *buf, size_t bufLen) {
	static const char *links[] = { "/proc/self/exe", "/proc/curproc/file", "/proc/self/path/a.out" };

	if(buf == 0 || bufLen == 0) return;
	buf[0] = 0;

	for(size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
		ssize_t len = readlink(links[i], buf, bufLen - 1);
		if(len >= 0) {
			buf[len] = 0;
			return;
		}
	}

	snprintf(buf, bufLen, "%s", arg ? arg : "");
}

void getDefaultPath(const char *arg, char *buf, size_t bufLen) {
	if(buf == 0 || bufLen == 0) return;
	getExePath(arg, buf, bufLen);
	char *exe = strrchr(buf, '/');
	if(exe) {
		*exe = 0;
	} else if(getcwd(buf, bufLen) == 0) {
		buf[0] = 0;
	}
}
