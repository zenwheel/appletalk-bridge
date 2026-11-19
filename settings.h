#ifndef __SETTINGS_H__
#define __SETTINGS_H__

#include <stdbool.h>

bool loadConfiguration(const char *path);
void setSetting(const char *name, const char *value);
char *getSetting(const char *name);
bool getBoolSetting(const char *name);
void deleteSetting(const char *name);
void deleteSettings(void);
void showSettings(void);

#endif
