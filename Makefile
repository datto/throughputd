BINARY_NAME = throughputd
SOURCES = $(wildcard *.c)
DEBUG := false
ifeq ($(DEBUG),true)
CFLAGS := -g -DDEBUG_ENABLED -Wall
else
CFLAGS := -O3 -Wall -Werror
endif

LDFLAGS := 
CC := gcc
LIBS = -lpcap -lpthread -lsqlite3

DESTDIR := 
PREFIX := /usr/local
BINDIR := bin

.PHONY: all clean

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(SOURCES:.c=.o)
	$(CC) $(LDFLAGS) -o $(BINARY_NAME) $(SOURCES:.c=.o) $(LIBS)

install: $(BIANRY_NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	install -m755 $(BINARY_NAME) $(DESTDIR)$(PREFIX)/$(BINDIR)/$(BINARY_NAME)

clean:
	rm -f *.o
	rm -f $(BINARY_NAME)
