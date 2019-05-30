CC      := clang
CFLAGS  := -m32 -Wall -g
LDFLAGS := -arch i386
LDLIBS  :=

.PHONY: all clean examples

all: winonux examples

winonux: winonux.c

clean:
	$(MAKE) --directory=examples clean
	rm -f *.o winonux

examples:
	$(MAKE) --directory=$@

