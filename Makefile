CC      := gcc
CFLAGS  := -Wall -g

.PHONY: all clean examples

all: winonux examples

winonux: winonux.c winonux.h

clean:
	$(MAKE) --directory=examples clean
	rm -f *.o winonux

examples:
	$(MAKE) --directory=$@

