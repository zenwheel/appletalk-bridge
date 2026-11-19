EXE  = appletalk-bridge
SRCS = main.c client.c path.c settings.c network.c ddp.c pcap.c log.c queue.c http.c rmq_api.c urlencode.c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

DEBUG    ?= 0
CC       ?= cc
CFLAGS   ?= -O2 -g
CFLAGS   += -std=gnu11 -Wall -Wextra -fstack-protector-strong
CPPFLAGS += -DDEBUG=$(DEBUG) -D_FORTIFY_SOURCE=2 -MMD -MP

# rabbitmq-c and json-c ship pkg-config files on every supported platform;
# libpcap and libcurl come from the base system on macOS, so link them directly.
PKGS      = librabbitmq json-c
CPPFLAGS += $(shell pkg-config --cflags $(PKGS))
LDLIBS    = $(shell pkg-config --libs $(PKGS)) -lpcap -lcurl -lpthread

ifeq ($(shell uname -s),Darwin)
	# uthash is header-only (brew install uthash); uuid_* lives in libSystem.
	BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
	ifneq ($(BREW_PREFIX),)
		CPPFLAGS += -I$(BREW_PREFIX)/include
	endif
else
	LDLIBS += -luuid
endif

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(OBJS) $(DEPS) $(EXE)

-include $(DEPS)
