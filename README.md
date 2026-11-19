# appletalk-bridge

A utility to bridge classic AppleTalk networks over the internet, heavily inspired by [abridge](http://www.synack.net/~bbraun/abridge.html) by Rob Braun.

You can run this utility on multiple systems on different networks and it will relay AppleTalk packets between them.  It uses a rabbitmq server to relay the network packets instead of a proprietary server which means it is efficient and scalable.  Rabbitmq also supports authentication and encryption so you can secure the network traffic as it traverses the wild internet.

The utility runs on an ethernet connected system (not wireless) and needs permission to capture packets (run it as root, or on Linux grant the binary `cap_net_raw,cap_net_admin`, see below).  It uses promiscuous mode on the specified network interface to capture all AppleTalk packets and relay them to the rabbitmq server.  Simultaneously it receives all packets from other clients from the rabbitmq server and relays them to your local network as if they were locally produced packets.

The packets must be captured and transmitted from the wired ethernet network, so you can't run it on the same system as an emulator or, say, a netatalk server as it cannot capture the loopback packets.  It is probably best to run it on a separate system, such as a raspberry pi.

It should capture EtherTalk packets introduced to the ethernet network from a LocalTalk network from a LocalTalk bridge like the AsantéTalk bridge but I haven't tried it myself.

## Installation

### Linux (Debian, Ubuntu, Raspberry Pi OS)

	sudo apt-get install -y build-essential pkg-config libpcap-dev librabbitmq-dev uuid-dev libjson-c-dev libcurl4-openssl-dev uthash-dev

NOTE: This will work well on a raspberry pi.

### macOS

	xcode-select --install
	brew install pkgconf rabbitmq-c json-c uthash

(libpcap, libcurl and the uuid functions come with macOS.)

### Compilation

	git clone https://github.com/zenwheel/appletalk-bridge.git
	cd appletalk-bridge
	make
	# create $HOME/.bridgerc (see below) and chmod 600 it
	sudo ./appletalk-bridge

Build with `make DEBUG=1` for verbose packet logging.

On Linux you can avoid running as root by granting the capture capabilities to the binary instead:

	sudo setcap cap_net_raw,cap_net_admin+eip ./appletalk-bridge
	./appletalk-bridge


## Configuration

Settings should be put in a `$HOME/.bridgerc` file that's in the format:

	# comment
	Key = value # trailing comment

A `#` starts a comment only at the start of a line or after whitespace, so values such as passwords may contain `#`.  Command line options override values from the configuration file.

The available keys are:

	Server = localhost # rabbitmq server address
	Port = 5672 # rabbitmq port
	APIPort = 15672 # rabbitmq API port for monitor mode, use -1 to disable using the API
	User = guest # username for rabbitmq
	Password = guest # password for the specified rabbitmq user
	VHost = / # what virtual host to use with rabbitmq (usually /)
	RunInForeground = true # set false to daemonize when launched (messages then go to syslog)
	UseSSL = false # use SSL with rabbitmq?
	APIUseSSL = <same as UseSSL> # use SSL with the rabbitmq API?
	SSLVerifyPeer = true # verify the server's certificate (against the system CAs unless SSLCACertificateFile is set)
	SSLVerifyHostname = true
	SSLCACertificateFile = <none>
	SSLClientCertificateFile = <none>
	SSLKeyFile = <none>
	MonitorMode = false # disable relaying packets, display packets that are sent to the rabbitmq server, does not require superuser privileges
	AMQPExchange = appleshare # name of rabbitmq exchange to create and use
	Interface = <first available>

Command line options: `-d` (run in background), `-r` (use SSL), `-m` (monitor mode), `-i <interface>`, `-s <server>`, `-p <port>`, `-u <user>`, `-x <password>`, `-c <config file>`, `-v`, `-h`.  Avoid `-x` on shared machines since other users can see command line arguments; put the password in the configuration file instead.

If you can't use `$HOME/.bridgerc` like because `sudo` doesn't pass your `$HOME` through, you can launch it with `sudo ./appletalk-bridge -c /path/to/config` instead.

Example `$HOME/.bridgerc`:

	# rabbitmq server:
	Server = localhost
	Port = 5671
	User = bridge
	Password = secret
	UseSSL = true

If the bridge loses its connection to the server it reconnects automatically, backing off up to a minute between attempts.

## Security

* Only AppleTalk (DDP) and AARP frames are captured and relayed; IP and other traffic on your network is never sent to the server.  However, AppleTalk traffic itself (AppleShare file transfers, printing, device names, MAC addresses) is visible to the server and to every other bridge on the exchange, so only share an exchange with people you trust.
* Use `UseSSL = true` whenever the server isn't on your own network; otherwise your password and traffic cross the internet unencrypted.  Keep `SSLVerifyPeer = true` (the default) so nobody can impersonate the server; for a self-signed server certificate set `SSLCACertificateFile` rather than turning verification off.
* Frames received from the server are only put onto your network if they are well-formed AppleTalk or AARP frames.
* The default RabbitMQ `guest` account only works from localhost; create a dedicated user for your bridges.

## Server Setup

If you want to set up your own rabbitmq server for your bridge, here's some starting points but there are lots of resources elsewhere that are too broad to cover here (rabbitmq is pretty complex and powerful):

### Linux

Debian and Ubuntu ship a usable `rabbitmq-server` package:

	sudo apt update
	sudo apt-get install -y rabbitmq-server
	sudo rabbitmq-plugins enable rabbitmq_management # for monitor mode's client list

For the latest release follow [https://www.rabbitmq.com/docs/install-debian](https://www.rabbitmq.com/docs/install-debian).  Then create a user for the bridges:

	sudo rabbitmqctl add_user bridge 'secret'
	sudo rabbitmqctl set_permissions bridge '.*' '.*' '.*'

See [https://www.rabbitmq.com/docs/ssl](https://www.rabbitmq.com/docs/ssl) to enable TLS.

### macOS

	brew install rabbitmq

## Changes

### 0.10

Upgrading from 0.9:

* Install `uthash-dev` (Linux) or `brew install uthash` (macOS); `ossp-uuid` and Homebrew's `libpcap` are no longer needed.
* `SSLVerifyPeer` now defaults to `true`.  If your server uses a self-signed certificate, set `SSLCACertificateFile` (or explicitly set `SSLVerifyPeer = false`).
* `APIUseSSL` now defaults to the value of `UseSSL`.
* The long option `--foreground` is now `--background` (it always meant background; `-d` is unchanged).
* Command line options now override the configuration file, and `#` only starts a comment at the start of a line or after whitespace.
* Update every bridge that shares an exchange; older bridges can still loop duplicated frames.

Security:

* Frames received from the server are only injected onto the local network if they are well-formed AppleTalk/AARP frames (previously any Ethernet frame was accepted).
* The packet decoder is bounds-checked; crafted packets could previously read past the end of the buffer.  Decoded names are sanitized before printing.
* Fixed memory corruption when listing clients in monitor mode (JSON reference counting) and a crash on API error responses.
* TLS certificates are verified by default against the system CA store, and the management API uses HTTPS when AMQP does.
* uthash is no longer cloned from GitHub at build time.
* Warns when the configuration file is readable by other users; the password is masked in debug output.

Fixes and improvements:

* Builds on current macOS and Linux (rabbitmq-c 0.11 through 0.18) with no warnings.
* Loop prevention now learns which MAC addresses are on the far side of the bridge, fixing a broadcast storm when the network delivered duplicate copies of injected frames.
* Automatically reconnects to the server, with backoff, if the connection drops.
* Packets are captured in immediate mode (no up-to-one-second delay) and are no longer truncated at 1024 bytes on macOS.
* Clean shutdown on SIGINT/SIGTERM; logs go to syslog when running in the background.
* Fixed NBP function decoding, 32-bit packet counter output, and stale entries in monitor mode's client list.
* Can run without root on Linux using capabilities (see Compilation).
