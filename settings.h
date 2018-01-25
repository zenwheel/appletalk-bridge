#ifndef __SETTINGS_H__
#define __SETTINGS_H__

void loadConfiguration(char *path);
void setSetting(char *name, char *value);
char *getSetting(char *name);
void deleteSetting(char *name);
void deleteSettings();
void showSettings();

#endif
