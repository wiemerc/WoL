#!/usr/bin/env python3
#
# memmap.py - small utility to print the memory map of a process on Linux (and probably other Unices as well)
#             *and* Windows (similiar to the pmap command found on Linux and Solaris)
#
# Copyright(C) 2019 Constantin Wiemer


import psutil
import os
import sys


#
# format size of the memory mapping so that it's human-readable
#
def fmtsize (size):
    if size > 1073741824:
        size = str(int(size / 1073741824)) + 'G'
    elif size > 1048576:
        size = str(int(size / 1048576)) + 'M'
    elif size > 1024:
        size = str(int(size / 1024)) + 'K'
    return size


p = psutil.Process(int(sys.argv[1]))
print('{:33}\t{:>5} / {:>5}\t{}\t{}'.format('ADDRESS RANGE', 'RSS', 'SIZE', 'PERM', 'NAME'))
for m in p.memory_maps(grouped=False):
    if sys.platform == 'win32':
        start = int(m.addr, 16)
        end   = start + int(m.rss)
        print('{:016x}-{:016x}\t{:>5} / {:>5}\t{}\t{}'.format(
            start,
            end,
            fmtsize(m.rss),
            '?',
            m.perms,
            os.path.basename(m.path)
        ))
    else:
        start, end = [int(x, 16) for x in m.addr.split('-')]
        print('{:016x}-{:016x}\t{:>5} / {:>5}\t{}\t{}'.format(
            start,
            end,
            fmtsize(m.rss),
            fmtsize(m.size),
            m.perms,
            os.path.basename(m.path)
        ))
