#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <uthash.h>
#include "settings.h"
#include "log.h"

// Settings are written during startup (before any threads exist) and only read
// afterwards, so no locking is needed.

typedef struct Setting {
	char *name;
	char *value;
	UT_hash_handle hh;
} Setting;

static Setting *settings = 0;

static char *trim(char *s) {
	while(isspace((unsigned char)*s)) s++;
	size_t len = strlen(s);
	while(len > 0 && isspace((unsigned char)s[len - 1]))
		s[--len] = 0;
	return s;
}

bool loadConfiguration(const char *path) {
	if(path == 0)
		return false;

	FILE *f = fopen(path, "r");
	if(f == 0) {
		logError("Can't load configuration (%s): %s", path, strerror(errno));
		return false;
	}

	struct stat st;
	if(fstat(fileno(f), &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)))
		logError("Warning: %s is accessible by other users but may contain your password (chmod 600 it)", path);

	char *line = 0;
	size_t cap = 0;
	while(getline(&line, &cap, f) != -1) {
		// a '#' at the start of a line or after whitespace starts a comment,
		// so values such as passwords may still contain '#'
		for(char *p = line; *p; p++) {
			if(*p == '#' && (p == line || isspace((unsigned char)p[-1]))) {
				*p = 0;
				break;
			}
		}

		char *eq = strchr(line, '=');
		if(eq == 0) continue;
		*eq = 0;

		char *key = trim(line);
		char *value = trim(eq + 1);
		if(*key == 0) continue;

		setSetting(key, value);
	}

	free(line);
	fclose(f);
	return true;
}

void setSetting(const char *name, const char *value) {
	if(name == 0 || name[0] == 0) return;
	if(value == 0 || value[0] == 0) return;

	char *copy = strdup(value);
	if(copy == 0) {
		logError("Out of memory storing setting %s", name);
		return;
	}

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	if(setting == 0) {
		setting = calloc(1, sizeof(Setting));
		if(setting == 0 || (setting->name = strdup(name)) == 0) {
			logError("Out of memory storing setting %s", name);
			free(setting);
			free(copy);
			return;
		}
		HASH_ADD_KEYPTR(hh, settings, setting->name, strlen(setting->name), setting);
	}

	free(setting->value);
	setting->value = copy;
}

char *getSetting(const char *name) {
	if(name == 0 || name[0] == 0) return 0;

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	return setting ? setting->value : 0;
}

bool getBoolSetting(const char *name) {
	const char *value = getSetting(name);
	if(value == 0)
		return false;
	return strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 ||
		strcasecmp(value, "on") == 0 || strcmp(value, "1") == 0;
}

static void freeSetting(Setting *setting) {
	free(setting->name);
	free(setting->value);
	free(setting);
}

void deleteSetting(const char *name) {
	if(name == 0 || name[0] == 0) return;

	Setting *setting = 0;
	HASH_FIND_STR(settings, name, setting);
	if(setting != 0) {
		HASH_DEL(settings, setting);
		freeSetting(setting);
	}
}

void deleteSettings(void) {
	Setting *setting = 0, *tmp = 0;
	HASH_ITER(hh, settings, setting, tmp) {
		HASH_DEL(settings, setting);
		freeSetting(setting);
	}
	settings = 0;
}

void showSettings(void) {
	logDebug("{");
	for(Setting *setting = settings; setting; setting = setting->hh.next) {
		bool secret = strcasecmp(setting->name, "Password") == 0;
		logDebug("\t\"%s\" = \"%s\"%s", setting->name, secret ? "********" : setting->value, setting->hh.next ? "," : "");
	}
	logDebug("}");
}
