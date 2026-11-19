#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stdbool.h>

// returns true if it got as far as consuming messages (even if the connection later dropped)
bool clientConnect(void);

#endif
