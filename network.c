#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "network.h"

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
		strncpy(buf, ifa->ifa_name, bufLen);
		break;
	}

	freeifaddrs(ifaddr);
}