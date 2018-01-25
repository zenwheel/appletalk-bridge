#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <uuid/uuid.h>
#include "main.h"
#include "client.h"
#include "path.h"
#include "settings.h"
#include "network.h"
#include "pcap.h"
#include "log.h"
#include "rmq_api.h"

bool m_run = true;

void handleInterrupt(int signal) {
	printf("\rCleaning up...\n");
	m_run = false;
}

void *clientLoop(void *ctx) {
	while(m_run) {
		showClients();
		if(m_run) sleep(10);
	}
	return 0;
}

void loadDefaults(int argc, char **argv) {
	uuid_t uuid;
	char buf[255];

	setSetting("Binary", getFilename(argv[0]));
	getExePath(argv[0], buf, sizeof(buf));
	setSetting("Executable", buf);
	getDefaultPath(argv[0], buf, sizeof(buf));
	setSetting("Directory", buf);
	char *home = getenv("HOME");
	if(home) {
		snprintf(buf, sizeof(buf), "%s/.bridgerc", home);
		setSetting("ConfigurationFile", buf);
	}
	setSetting("Server", "localhost");
	setSetting("Port", "5672");
	setSetting("APIPort", "15672"); // use -1 to disable using the API
	setSetting("User", "guest");
	setSetting("Password", "guest");
	setSetting("VHost", "/");
	setSetting("RunInForeground", "true");
	setSetting("InForeground", "true");
	setSetting("UseSSL", "false");
	setSetting("APIUseSSL", "false");
	setSetting("SSLVerifyPeer", "false");
	setSetting("SSLVerifyHostname", "true");
	setSetting("SSLCACertificateFile", 0);
	setSetting("SSLClientCertificateFile", 0);
	setSetting("SSLKeyFile", 0);
	setSetting("MonitorMode", "false");
	setSetting("AMQPExchange", "appleshare");
	gethostname(buf, sizeof(buf));
	setSetting("Hostname", buf);
	getInterface(buf, sizeof(buf));
	if(buf[0])
		setSetting("Interface", buf);
	uuid_generate(uuid);
	uuid_unparse_lower(uuid, buf);
	setSetting("ClientID", buf);
}

void usage(char *exe) {
	logMessage("Usage: %s [-h] [-d] [-p portnum]", exe);
	logMessage("");
	logMessage("-d | --background   Run in background");
	logMessage("-r | --ssl          Use SSL");
	logMessage("-m | --monitor      Monitor Mode (don't relay packets, just display packet queue)");
	logMessage("-s | --server <s>   Specify server to connect to");
	logMessage("-p | --port <#>     Specify port number to connect to");
	logMessage("-u | --user <u>     Specify username to authenticate with");
	logMessage("-x | --password <p> Specify password to authenticate with");
	logMessage("-c | --config c>    Specify configuration file to load");
	logMessage("-v | --version      Display version and exit");
	logMessage("-h | --help         This message");
}

int main(int argc, char **argv) {
	struct option o[] = {
		{ "foreground", no_argument, 0, 'd' },
		{ "ssl", no_argument, 0, 'r' },
		{ "monitor", no_argument, 0, 'm' },
		{ "help", no_argument, 0, 'h' },
		{ "interface", required_argument, 0, 'i' },
		{ "server", required_argument, 0, 's' },
		{ "port", required_argument, 0, 'p' },
		{ "user", required_argument, 0, 'u' },
		{ "password", required_argument, 0, 'x' },
		{ "config", required_argument, 0, 'c' },
		{ "version", no_argument, 0, 'v' },
		{0, 0, 0, 0}
	};

	char c;
	loadDefaults(argc, argv);

	while((c = getopt_long(argc, argv, "drhmi:s:p:u:x:c:v", o, 0)) != (char)-1 ) {
		switch(c) {
			case 'd':
				setSetting("RunInForeground", "false");
				break;
			case 'r':
				setSetting("UseSSL", "true");
				break;
			case 'm':
				setSetting("MonitorMode", "true");
				break;
			case 'i':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("Interface", optarg);
				break;
			case 's':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("Server", optarg);
				break;
			case 'p':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("Port", optarg);
				break;
			case 'u':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("User", optarg);
				break;
			case 'x':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("Password", optarg);
				break;
			case 'c':
				if(!optarg) {
					usage(argv[0]);
					exit(-1);
				}
				setSetting("ConfigurationFile", optarg);
				break;
			case 'v':
				logMessage("%s %s", APP_NAME, VERSION);
				exit(0);
			case 'h':
				usage(argv[0]);
				exit(0);
		}
	}

	if(getSetting("ConfigurationFile") != 0)
		loadConfiguration(getSetting("ConfigurationFile"));

	showSettings();

	signal(SIGINT, handleInterrupt);

	if(atoi(getSetting("Port")) == 0) {
		logError("Invalid port specified: %s", getSetting("Port"));
		exit(-1);
	}

	if(atoi(getSetting("APIPort")) == 0) {
		logError("Invalid API port specified: %s", getSetting("APIPort"));
		exit(-1);
	}

	if(strcmp(getSetting("MonitorMode"), "false") == 0 && geteuid() != 0) {
		logError("Must be run as superuser to capture packets.");
		exit(-1);
	}

#if !DEBUG
	if(strcmp(getSetting("RunInForeground"), "false") == 0 && strcmp(getSetting("MonitorMode"), "false") == 0) {
		int pid = fork();
		if(pid == -1) {
			logError("Unable to create background process: %s", strerror(errno));
			exit(-1);
		}
		if(pid > 0) // parent process, silently exit
			exit(0);
		setSetting("InForeground", "false");
		setsid();
	}
#endif

	pthread_t clientThread;

	if(strcmp(getSetting("MonitorMode"), "false") == 0)
		startPacketCapture();
	else {
		pthread_attr_t defaultattrs;
		pthread_attr_init(&defaultattrs);

		if(pthread_create(&clientThread, &defaultattrs, clientLoop, 0) != 0) {
			logError("Couldn't create client thread");
			setSetting("MonitorMode", "false");
		}
		pthread_attr_destroy(&defaultattrs);
	}

	while(m_run) {
		clientConnect();
		if(m_run) usleep(500000);
		break;
	}

	if(strcmp(getSetting("MonitorMode"), "false") != 0) {
		pthread_cancel(clientThread);
		pthread_join(clientThread, 0);
	}

	stopPacketCapture();

	return 0;
}
