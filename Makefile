CC      := clang
AS  	:= as
CFLAGS  := -std=c99 -D_DEFAULT_SOURCE -Wall -Wno-int-to-pointer-cast -Wno-compare-distinct-pointer-types -g
LDFLAGS := -Wl,-Ttext,0x00800000 -Wl,-Tdata,0x00C00000 -Wl,-Tbss,0x01000000

.PHONY: all clean libs examples

all: wol libs examples

wol.o: wol.c wol.h

thunk.o: thunk.s
	$(AS) -o $@ $^

wol: wol.o thunk.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	$(MAKE) --directory=libs clean
	$(MAKE) --directory=examples clean
	rm -f *.o wol

libs:
	$(MAKE) --directory=$@

examples:
	$(MAKE) --directory=$@

history:
	git log --format="format:%h %ci %s"
