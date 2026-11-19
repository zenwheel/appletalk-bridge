#ifndef __MAIN_H__
#define __MAIN_H__

#include <signal.h>

#define APP_NAME "appletalk-bridge"
#define VERSION "0.10"
#define USER_AGENT APP_NAME "/" VERSION

// cleared by SIGINT/SIGTERM (or a fatal error) to shut every thread down
extern volatile sig_atomic_t m_run;

#endif
