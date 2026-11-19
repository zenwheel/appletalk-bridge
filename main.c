#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <uuid/uuid.h>
#include <curl/curl.h>
#include "main.h"
#include "client.h"
#include "path.h"
#include "settings.h"
#include "network.h"
#include "pcap.h"
#include "log.h"
#include "rmq_api.h"

#define MAX_RECONNECT_DELAY 60

volatile sig_atomic_t m_run = 1;

static void handleSignal(int sig) {
	(void)sig;
	m_run = 0;
}

// sleep for up to seconds, returning early on shutdown
static void interruptibleSleep(unsigned seconds) {
	for(unsigned i = 0; i < seconds && m_run; i++)
		sleep(1);
}

static void *clientLoop(void *ctx) {
	(void)ctx;
	while(m_run) {
		showClients();
		interruptibleSleep(10);
	}
	return 0;
}

static void loadDefaults(char **argv) {
	uuid_t uuid;
	char buf[1024];

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
	// APIUseSSL defaults to the value of UseSSL (see main)
	setSetting("SSLVerifyPeer", "true");
	setSetting("SSLVerifyHostname", "true");
	setSetting("MonitorMode", "false");
	setSetting("AMQPExchange", "appleshare");
	if(gethostname(buf, sizeof(buf)) == 0) {
		buf[sizeof(buf) - 1] = 0;
		setSetting("Hostname", buf);
	}
	getInterface(buf, sizeof(buf));
	if(buf[0])
		setSetting("Interface", buf);
	uuid_generate(uuid);
	uuid_unparse_lower(uuid, buf);
	setSetting("ClientID", buf);
}

static void usage(const char *exe) {
	logMessage("Usage: %s [options]", exe);
	logMessage("%s", "");
	logMessage("-d | --background     Run in background (logs go to syslog)");
	logMessage("-r | --ssl            Use SSL");
	logMessage("-m | --monitor        Monitor Mode (don't relay packets, just display packet queue)");
	logMessage("-i | --interface <i>  Specify network interface to bridge");
	logMessage("-s | --server <s>     Specify server to connect to");
	logMessage("-p | --port <#>       Specify port number to connect to");
	logMessage("-u | --user <u>       Specify username to authenticate with");
	logMessage("-x | --password <p>   Specify password to authenticate with (visible to other users; prefer the config file)");
	logMessage("-c | --config <c>     Specify configuration file to load");
	logMessage("-v | --version        Display version and exit");
	logMessage("-h | --help           This message");
}

static bool validPort(const char *value, bool allowDisabled) {
	if(value == 0)
		return false;
	char *end = 0;
	errno = 0;
	long port = strtol(value, &end, 10);
	if(errno != 0 || end == value || *end != 0)
		return false;
	if(allowDisabled && port < 0)
		return true;
	return port >= 1 && port <= 65535;
}

static void daemonize(void) {
	pid_t pid = fork();
	if(pid == -1) {
		logError("Unable to create background process: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(pid > 0) // parent process, silently exit
		exit(EXIT_SUCCESS);

	setsid();
	if(chdir("/") != 0) { /* not fatal */ }
	int fd = open("/dev/null", O_RDWR);
	if(fd >= 0) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if(fd > STDERR_FILENO)
			close(fd);
	}
	openlog(APP_NAME, LOG_PID, LOG_DAEMON);
	setSetting("InForeground", "false");
}

int main(int argc, char **argv) {
	static const struct option o[] = {
		{ "background", no_argument, 0, 'd' },
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

	// command line options are applied after the configuration file so they override it
	struct { const char *name; const char *value; } overrides[16];
	size_t overrideCount = 0;
	const char *configFile = 0;
	int c;

	loadDefaults(argv);

	while((c = getopt_long(argc, argv, "drhmi:s:p:u:x:c:v", o, 0)) != -1) {
		const char *name = 0, *value = optarg;
		switch(c) {
			case 'd': name = "RunInForeground"; value = "false"; break;
			case 'r': name = "UseSSL"; value = "true"; break;
			case 'm': name = "MonitorMode"; value = "true"; break;
			case 'i': name = "Interface"; break;
			case 's': name = "Server"; break;
			case 'p': name = "Port"; break;
			case 'u': name = "User"; break;
			case 'x': name = "Password"; break;
			case 'c': configFile = optarg; break;
			case 'v':
				logMessage("%s %s", APP_NAME, VERSION);
				exit(EXIT_SUCCESS);
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
		if(name && overrideCount < sizeof(overrides) / sizeof(overrides[0])) {
			overrides[overrideCount].name = name;
			overrides[overrideCount].value = value;
			overrideCount++;
		}
	}

	if(configFile) {
		// an explicitly requested file must exist
		if(!loadConfiguration(configFile))
			exit(EXIT_FAILURE);
	} else if(fileExists(getSetting("ConfigurationFile"))) {
		loadConfiguration(getSetting("ConfigurationFile"));
	}

	for(size_t i = 0; i < overrideCount; i++)
		setSetting(overrides[i].name, overrides[i].value);

	if(getSetting("APIUseSSL") == 0)
		setSetting("APIUseSSL", getBoolSetting("UseSSL") ? "true" : "false");

	showSettings();

	if(!validPort(getSetting("Port"), false)) {
		logError("Invalid port specified: %s", getSetting("Port"));
		exit(EXIT_FAILURE);
	}

	if(!validPort(getSetting("APIPort"), true)) {
		logError("Invalid API port specified: %s", getSetting("APIPort"));
		exit(EXIT_FAILURE);
	}

	bool monitor = getBoolSetting("MonitorMode");
	if(!monitor && getSetting("Interface") == 0) {
		logError("No usable network interface found; specify one with -i or Interface =");
		exit(EXIT_FAILURE);
	}

	if(!getBoolSetting("UseSSL") && strcmp(getSetting("Server"), "localhost") != 0 && strcmp(getSetting("Server"), "127.0.0.1") != 0)
		logError("Warning: UseSSL is off; your password and AppleTalk traffic are sent unencrypted");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handleSignal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGTERM, &sa, 0);
	signal(SIGPIPE, SIG_IGN);

#if !DEBUG
	if(!getBoolSetting("RunInForeground") && !monitor)
		daemonize();
#endif

	// must happen before any threads exist
	curl_global_init(CURL_GLOBAL_DEFAULT);

	pthread_t clientThread;
	bool clientThreadRunning = false;

	if(!monitor) {
		if(!startPacketCapture())
			exit(EXIT_FAILURE);
	} else if(atoi(getSetting("APIPort")) > 0) {
		if(pthread_create(&clientThread, 0, clientLoop, 0) == 0)
			clientThreadRunning = true;
		else
			logError("Couldn't create client thread");
	}

	unsigned delay = 1;
	while(m_run) {
		if(clientConnect())
			delay = 1;
		if(!m_run)
			break;
		logError("Lost connection to %s; reconnecting in %u seconds", getSetting("Server"), delay);
		interruptibleSleep(delay);
		if(delay < MAX_RECONNECT_DELAY)
			delay = delay * 2 > MAX_RECONNECT_DELAY ? MAX_RECONNECT_DELAY : delay * 2;
	}
	logMessage("Cleaning up...");

	if(clientThreadRunning)
		pthread_join(clientThread, 0);

	stopPacketCapture();
	curl_global_cleanup();
	logMessage("Done.");
	deleteSettings();

	return EXIT_SUCCESS;
}
