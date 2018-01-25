#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include "path.h"

bool fileExists(char *path) {
	struct stat statbuf;
	
	if(path == 0) return false;
	if(stat(path, &statbuf) != 0)
		return false;
	return true;
}

char *getFilename(char *path) {
	if(path == 0) return 0;
	char *filename = strrchr(path, '/');
	if(filename == 0)
		return path;
	filename++;
	return filename;
}

void getExePath(char *arg, char *buf, size_t bufLen) {
	if(buf == 0 || bufLen == 0) return;
	buf[0] = 0;
	
	if(fileExists("/proc/self/exe")) {
		int len = readlink("/proc/self/exe", buf, bufLen - 1);
		if(len != -1) {
			buf[len] = 0;
			return;
		}
	}
	if(fileExists("/proc/curproc/file")) {
		int len = readlink("/proc/curproc/file", buf, bufLen - 1);
		if(len != -1) {
			buf[len] = 0;
			return;
		}
	}
	if(fileExists("/proc/self/path/a.out")) {
		int len = readlink("/proc/self/path/a.out", buf, bufLen - 1);
		if(len != -1) {
			buf[len] = 0;
			return;
		}
	}
	
	strncpy(buf, arg, bufLen);
}

void getDefaultPath(char *arg, char *buf, size_t bufLen) {
	if(buf == 0 || bufLen == 0) return;
	getExePath(arg, buf, bufLen);
	char *exe = strrchr(buf, '/');
	if(exe) {
		*exe = 0;
	} else {
		getcwd(buf, bufLen);
	}
}