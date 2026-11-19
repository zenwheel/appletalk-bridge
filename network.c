#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "network.h"

// pick the first interface that is up, running, not loopback and has an IPv4 address
void getInterface(char *buf, size_t bufLen) {
	if(buf == 0 || bufLen == 0) return;
	buf[0] = 0;

	struct ifaddrs *ifaddr;
	if(getifaddrs(&ifaddr) == -1) return;

	for(struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if(ifa->ifa_addr == 0) continue;
		if(ifa->ifa_addr->sa_family != AF_INET) continue;
		if(ifa->ifa_flags & IFF_LOOPBACK) continue;
		if((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_RUNNING) == 0) continue;
		snprintf(buf, bufLen, "%s", ifa->ifa_name);
		break;
	}

	freeifaddrs(ifaddr);
}
