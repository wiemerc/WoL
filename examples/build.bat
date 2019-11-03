cl strtoupper.c /link /entry:start /subsystem:console
cl winhello.c /link /entry:start /subsystem:console kernel32.lib
cl sehtest.c /FAs /link /entry:start /subsystem:console kernel32.lib msvcrt.lib vcruntime.lib
