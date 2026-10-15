CC       ?= cc
CFLAGS   ?= -O3 -Wall -Wextra -pthread
CPPFLAGS += -I..
LDFLAGS  ?=
LDLIBS   ?= -lssl -lcrypto $(SCTP_LIB) -lm -lpthread
SCTP_LIB ?= -lsctp

DBG_CFLAGS  := -g -fsanitize=address,undefined -fno-omit-frame-pointer
DBG_LDFLAGS := -fsanitize=address,undefined

SRCS := main.c client.c server.c tunnel.c queue.c
IPERF_LIB = ../.libs/libiperf.a

REL_BIN  := ../../iperf-tunnel
REL_OBJS := $(addprefix build/release/,$(SRCS:.c=.o))

DBG_BIN  := ../../iperf-tunnel-debug
DBG_OBJS := $(addprefix build/debug/,$(SRCS:.c=.o))

.PHONY: all release debug clean
all: release
release: $(REL_BIN)
debug:   $(DBG_BIN)

$(REL_BIN): $(REL_OBJS) $(IPERF_LIB)
	$(CC) $(LDFLAGS) -s -o $@ $(REL_OBJS) $(IPERF_LIB) $(LDLIBS)

$(DBG_BIN): $(DBG_OBJS) $(IPERF_LIB)
	$(CC) $(LDFLAGS) $(DBG_LDFLAGS) -o $@ $(DBG_OBJS) $(IPERF_LIB) $(LDLIBS)

$(IPERF_LIB): $(wildcard ../*.c ../*.h)
	@test -f ../Makefile || { echo "сначала выполните ./configure в корне репозитория"; exit 1; }
	$(MAKE) -C .. libiperf.la

build/release build/debug:
	mkdir -p $@

build/release/%.o: %.c | build/release
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/debug/%.o: %.c | build/debug
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DBG_CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -rf build $(REL_BIN) $(DBG_BIN)

-include $(REL_OBJS:.o=.d) $(DBG_OBJS:.o=.d)
