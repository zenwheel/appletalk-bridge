ifeq ($(OS),Windows_NT)
	detected_OS := Windows
else
	detected_OS := $(shell uname -s)
endif
CC=gcc
SRCS=main.c client.c path.c settings.c network.c ddp.c pcap.c log.c queue.c http.c rmq_api.c urlencode.c
OBJS=$(subst .c,.o,$(SRCS))
EXE=appletalk-bridge
CFLAGS=-DDEBUG=0
LDFLAGS=
JSON_CFLAGS=
LIBS=-lrabbitmq -lpcap -lpthread -luuid -lcurl -ljson-c
ifeq ($(detected_OS),Darwin)
	JSON_CFLAGS=$(shell pkg-config --cflags json-c)
	LDFLAGS=$(shell pkg-config --libs-only-L json-c)
endif

all: $(EXE)

clean:
	rm -f $(OBJS) $(EXE)

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

settings.c: uthash

uthash:
	git clone https://github.com/troydhanson/uthash.git

%.o: %.c
	$(CC) $(CFLAGS) -c $<

rmq_api.o: rmq_api.c
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -c $<
