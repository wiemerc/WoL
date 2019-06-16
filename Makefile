CC      := clang
CFLAGS  := -std=c99 -m32 -D_DEFAULT_SOURCE -Wall -Wno-int-to-pointer-cast -Wno-compare-distinct-pointer-types -g -Wl,-Ttext,0x00800000 -Wl,-Tdata,0x00C00000 -Wl,-Tbss,0x01000000

.PHONY: all clean libs examples

all: winonux libs examples

winonux: winonux.c winonux.h
	$(CC) $(CFLAGS) winonux.c -o winonux

clean:
	$(MAKE) --directory=libs clean
	$(MAKE) --directory=examples clean
	rm -f *.o winonux

libs:
	$(MAKE) --directory=$@

examples:
	$(MAKE) --directory=$@

history:
	git log --format="format:%h %ci %s"
