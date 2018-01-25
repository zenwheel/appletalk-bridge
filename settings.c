#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "settings.h"
#include "uthash/src/uthash.h"
#include "path.h"
#include "log.h"

typedef struct Setting {
	char name[255];
	char value[255];
	UT_hash_handle hh;
} Setting;

Setting *settings = 0;

void loadConfiguration(char *path) {
	char buf[255];

	if(path == 0)
		return;
	if(fileExists(path) == false) {
		logDebug("Configuration file '%s' doesn't exist.", path);
		return;
	}

	FILE *f = fopen(path, "r");

	if(f == 0) {
		logError("Can't load configuration (%s): %s", path, strerror(errno));
		return;
	}

	while(fgets(buf, sizeof(buf), f)) {
		// remove comments
		char *p = strchr(buf, '#');
		if(p) *p = 0;

		// trim
		while(strlen(buf) > 0 && isspace(buf[strlen(buf) - 1]))
			buf[strlen(buf) - 1] = 0;

		if(*buf == 0) continue;
		p = strchr(buf, '=');
		if(p == 0) continue;
		*(p++) = 0; // skip =

		// trim key and value
		while(strlen(buf) > 0 &&  isspace(buf[strlen(buf) - 1]))
			buf[strlen(buf) - 1] = 0;
		while(isspace(*p)) p++;

		setSetting(buf, p);
	}

	fclose(f);
}

void setSetting(char *name, char *value) {
	if(name == 0 || name[0] == 0) return;
	if(value == 0 || value[0] == 0) return;

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	if(setting == 0) {
		setting = (Setting*)malloc(sizeof(Setting));
		strncpy(setting->name, name, sizeof(setting->name));
		HASH_ADD_STR(settings, name, setting);
	}

	strncpy(setting->value, value, sizeof(setting->value));
}

char *getSetting(char *name) {
	if(name == 0 || name[0] == 0) return 0;

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	if(setting != 0)
		return setting->value;

	return 0;
}

void deleteSetting(char *name) {
	if(name == 0 || name[0] == 0) return;

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	if(setting != 0) {
		HASH_DEL(settings, setting);
		free(setting);
	}
}

void deleteSettings() {
	Setting *setting = 0, *tmp = 0;
	HASH_ITER(hh, settings, setting, tmp) {
		HASH_DEL(settings, setting);
		free(setting);
	}
	settings = 0;
}

void showSettings() {
	Setting *setting = 0;

	logDebug("{");
	for(setting = settings; setting; setting = setting->hh.next) {
		logDebug("\t\"%s\" = \"%s\"%s", setting->name, setting->value, setting->hh.next ? "," : "");
	}
	logDebug("}");
}
