# appletalk-bridge

A utility to bridge classic AppleTalk networks over the internet, heavily inspired by [abridge](http://www.synack.net/~bbraun/abridge.html) by Rob Braun.

You can run this utility on multiple systems on different networks and it will relay AppleTalk packets between them.  It uses a rabbitmq server to relay the network packets instead of a proprietary server which means it is efficient and scalable.  Rabbitmq also supports authentication and encryption so you can secure the network traffic as it traverses the wild internet.

The utility runs on an ethernet connected system (not wireless) and requires superuser privileges to run.  It uses promiscuous mode on the specified network interface to capture all AppleTalk packets and relay them to the rabbitmq server.  Simultaneously it receives all packets from other clients from the rabbitmq server and relays them to your local network as if they were locally produced packets.

The packets must be captured and transmitted from the wired ethernet network, so you can't run it on the same system as an emulator or, say, a netatalk server as it cannot capture the loopback packets.  It is probably best to run it on a separate system, such as a raspberry pi.

It should capture EtherTalk packets introduced to the ethernet network from a LocalTalk network from a LocalTalk bridge like the AsantéTalk bridge but I haven't tried it myself.

## Installation

### Linux

	sudo apt-get install -y libpcap-dev librabbitmq-dev uuid-dev libjson-c-dev libcurl4-gnutls-dev

NOTE: This will work well on a raspberry pi.

### Mac OS X

	brew install libpcap rabbitmq-c ossp-uuid json-c

### Compilation

	git clone https://github.com/zenwheel/appletalk-bridge.git
	cd appletalk-bridge
	make
	# create $HOME/.bridgerc (see below)
	sudo ./appletalk-bridge


## Configuration

Settings should be put in a `$HOME/.bridgerc` file that's in the format:

	# comment
	Key = value

The available keys are:

	Server = localhost # rabbitmq server address
	Port = 5672 # rabbitmq port
	APIPort = 15672 # rabbitmq API port for monitor mode, use -1 to disable using the API
	User = guest # username for rabbitmq
	Password = guest # password for the specified rabbitmq user
	VHost = / # what virtual host to use with rabbitmq (usually /)
	RunInForeground = true # set false to daemonize when launched
	UseSSL = false # use SSL with rabbitmq?
	APIUseSSL = false # use SSL with the rabbitmq API?
	SSLVerifyPeer = false
	SSLVerifyHostname = true
	SSLCACertificateFile = <none>
	SSLClientCertificateFile = <none>
	SSLKeyFile = <none>
	MonitorMode = false # disable relaying packets, display packets that are sent to the rabbitmq server, does not require superuser privileges
	AMQPExchange = appleshare # name of rabbitmq exchange to create and use
	Interface = <first available>

If you can't use `$HOME/.bridgerc` like because `sudo` doesn't pass your `$HOME` through, you can launch it with `sudo ./appletalk-bridge -c /path/to/config` instead.

Example `$HOME/.bridgerc`:

	# rabbitmq server:
	Server = localhost
	Port = 5671
	User = guest
	Password = guest
	UseSSL = true

## Server Setup

If you want to set up your own rabbitmq server for your bridge, here's some starting points but there are lots of resources elsewhere that are too broad to cover here (rabbitmq is pretty complex and powerful):

### Linux

Follow the instructions here to configure the erlang and rabbitmq package sources:

* [https://packages.erlang-solutions.com/erlang/](https://packages.erlang-solutions.com/erlang/)
* [http://www.rabbitmq.com/install-debian.html](http://www.rabbitmq.com/install-debian.html)

Then:

	sudo apt update
	sudo apt-get install -y rabbitmq-server erlang-ssl

### Mac OS X

	brew install rabbitmq
