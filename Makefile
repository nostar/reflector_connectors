# Reflector Connectors — single-file C bridges
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=

PROGS = dmrcon refcon ysfcon dgidcon xrfcon

.PHONY: all clean

all: $(PROGS)

dmrcon: dmrcon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

refcon: refcon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

ysfcon: ysfcon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dgidcon: dgidcon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

xrfcon: xrfcon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGS)
