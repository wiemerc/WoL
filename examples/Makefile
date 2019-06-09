CC      := i686-w64-mingw32-gcc
CFLAGS  := -Wall -g
LDFLAGS := -s -nostdlib -e _start
LDLIBS  := -lkernel32

.PHONY: all clean

all: strtoupper.exe winhello.exe kernel32.dll

clean:
	rm -f *.o *.exe *.dll

strtoupper.exe: strtoupper.o
	$(CC) $(LDFLAGS) -o $@ $^

winhello.exe: cwcrt0.o winhello.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

kernel32.dll: kernel32.c kernel32.h
	$(CC) -shared -o kernel32.dll kernel32.c