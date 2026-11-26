CC      ?= cc
TARGET  := kreamlink
SRCS    := src/main.c src/config.c src/control.c src/log.c src/crypto.c src/ws.c src/hub.c src/agent.c src/workers.c
OBJS    := $(SRCS:.c=.o)

UNAME_S := $(shell uname -s)

CFLAGS  := -std=c11 -O2 -Wall -Wextra -Iinclude -pthread
LDFLAGS := -pthread

ifeq ($(UNAME_S),Darwin)
    CFLAGS += -D_DARWIN_C_SOURCE
    # Auto-detect Homebrew OpenSSL on Apple Silicon or Intel macOS
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        CFLAGS  += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib
    else ifneq ($(wildcard /opt/homebrew/opt/openssl@3/include),)
        CFLAGS  += -I/opt/homebrew/opt/openssl@3/include
        LDFLAGS += -L/opt/homebrew/opt/openssl@3/lib
    else ifneq ($(wildcard /usr/local/opt/openssl@3/include),)
        CFLAGS  += -I/usr/local/opt/openssl@3/include
        LDFLAGS += -L/usr/local/opt/openssl@3/lib
    endif
    LDLIBS := -lssl -lcrypto
else
    CFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
    PKG_SSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
    PKG_SSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)
    CFLAGS += $(PKG_SSL_CFLAGS)
    ifeq ($(PKG_SSL_LIBS),)
        LDLIBS := -lssl -lcrypto
    else
        LDLIBS := $(PKG_SSL_LIBS)
    endif
endif

PREFIX ?= /usr/local

.PHONY: all clean install test test-unit

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/%.o: src/%.c include/kreamlink.h
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

tests/test_core: tests/test_core.c src/ws.c src/hub.c src/agent.c src/config.o src/control.o src/crypto.o src/log.o src/workers.o include/kreamlink.h
	$(CC) $(CFLAGS) -UNDEBUG $(LDFLAGS) -o $@ $< src/config.o src/control.o src/crypto.o src/log.o src/workers.o $(LDLIBS)

test-unit: $(TARGET) tests/test_core
	bash tests/test_core.sh

test: test-unit
	./tests/test_core --test-accept
	./tests/test_core --test-isolation
	bash tests/test_e2e.sh

clean:
	rm -f $(OBJS) $(TARGET) tests/test_core
