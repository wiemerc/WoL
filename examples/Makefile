CC      := i686-w64-mingw32-gcc
CFLAGS  := -Wall -g
LDFLAGS := -s -nostdlib -e _start
LDLIBS  := -lkernel32

.PHONY: all clean

all: strtoupper.exe winhello.exe sehtest.exe

clean:
	rm -f *.o *.obj *.exe

strtoupper.exe: strtoupper.o
	$(CC) $(LDFLAGS) -o $@ $^

winhello.exe: winhello.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

sehtest.exe: sehtest.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
