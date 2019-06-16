CC      := i686-w64-mingw32-gcc
CFLAGS  := -Wall -g
LDFLAGS := -s -nostdlib -e _start

.PHONY: all clean

all: kernel32.dll

clean:
	rm -f *.o *.dll

kernel32.dll: kernel32.c kernel32.h
	$(CC) -shared $(LDFLAGS) -o kernel32.dll kernel32.c