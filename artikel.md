# Gastarbeiter Teil 1 - Windows-Programme auf Unix ausführen

## Einführung

Nachdem ich einen Emulator für Amiga-Programme geschrieben hatte (siehe [VADM](https://github.com/wiemerc/VADM)) war ich neugierig geworden, ob ich auch einen Emulator für Windows-Programme schreiben könnte. Das so etwas grundsätzlich möglich ist war mir klar, das [WINE-Projekt](https://www.winehq.org) macht ja genau das.

Gute Beschreibung des PE-Formats: _Peering Inside the PE_ und die offizielle PE-Spezifikation von Microsoft

PE wurde so entworfen, dass das ganze Executable am Stück in den Speicher geladen werden kann (mit Memory-mapped IO) => `mmap` unter Unix

Es wird davon ausgegangen, dass das Executable immer an der gleichen Adresse (0x00400000) geladen wird, deswegen gibt es keine Relocation-Informationen => Flag `MAP_FIXED`. `mmap` mit `MAP_FIXED` funktioniert nur mit 32-Bit Executables (Option `-m32`) bzw. Prozessen. Bei 64-Bit-Prozessen sind unter macOS die unteren 4GB des Adressraums für den Kernel reserviert.


### Speicherlayout 32 / 64 Bit

#### 32 Bits
```
In [1]: import psutil

In [2]: p = [p for p in psutil.process_iter() if p.name() == 'winoux'][0]

In [3]: [(x.addr, x.path) for x in p.memory_maps(grouped=False)]
Out[3]:
[('0000000000056000-0000000000057000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('0000000000057000-0000000000058000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('0000000000058000-0000000000059000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('0000000000059000-000000000005b000', '[prv]'),
 ('000000000005b000-000000000005c000', '[ali]'),
 ('000000000005c000-000000000005d000', '[ali]'),
 ('000000000005d000-000000000005e000', '[nul]'),
 ('000000000005e000-0000000000069000', '[prv]'),
 ('0000000000069000-000000000006a000', '[nul]'),
 ('000000000006a000-000000000006b000', '[nul]'),
 ('000000000006b000-0000000000076000', '[prv]'),
 ('0000000000076000-0000000000077000', '[nul]'),
 ('0000000000077000-0000000000078000', '[prv]'),
 ('00000000000f5000-0000000000130000', '/usr/lib/dyld'),
 ('0000000000130000-0000000000133000', '/usr/lib/dyld'),
 ('0000000000133000-0000000000159000', '[prv]'),
 ('0000000000159000-000000000016e000', '/usr/lib/dyld'),
 ('0000000000400000-0000000000401000',
  '/Users/consti/Programmieren/WINOUX/examples/strtoupper.exe'),
 ('0000000078600000-0000000078700000', '[prv]'),
 ('0000000078800000-0000000079000000', '[prv]'),
 ('00000000a6c00000-00000000a6e00000',
  '/private/var/db/dyld/dyld_shared_cache_i386'),
 ('00000000a6e00000-00000000a6f47000',
  '/private/var/db/dyld/dyld_shared_cache_i386'),
 ('00000000aaf47000-00000000aef90000', '[cow]'),
 ('00000000bbfab000-00000000bf7ab000', '[nul]'),
 ('00000000bf7ab000-00000000bffab000', '[prv]'),
 ('00000000ffff3000-00000000ffff4000', '[shm]')]
 ```

#### 64 Bits
```
[('000000010c1cc000-000000010c1cd000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('000000010c1cd000-000000010c1ce000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('000000010c1ce000-000000010c1cf000',
  '/Users/consti/Programmieren/WINOUX/winoux'),
 ('000000010c1cf000-000000010c1d1000', '[prv]'),
 ('000000010c1d1000-000000010c1d2000', '[ali]'),
 ('000000010c1d2000-000000010c1d3000', '[ali]'),
 ('000000010c1d3000-000000010c1d4000', '[nul]'),
 ('000000010c1d4000-000000010c1e9000', '[prv]'),
 ('000000010c1e9000-000000010c1ea000', '[nul]'),
 ('000000010c1ea000-000000010c1eb000', '[nul]'),
 ('000000010c1eb000-000000010c200000', '[prv]'),
 ('000000010c200000-000000010c201000', '[nul]'),
 ('000000010c201000-000000010c202000', '[prv]'),
 ('0000000119c17000-0000000119c55000', '/usr/lib/dyld'),
 ('0000000119c55000-0000000119c58000', '/usr/lib/dyld'),
 ('0000000119c58000-0000000119c8c000', '[prv]'),
 ('0000000119c8c000-0000000119ca2000', '/usr/lib/dyld'),
 ('00007fe730c00000-00007fe730d00000', '[prv]'),
 ('00007fe731000000-00007fe731800000', '[prv]'),
 ('00007fff4fa34000-00007fff53234000', '[nul]'),
 ('00007fff53234000-00007fff53a34000', '[prv]'),
 ('00007fff8002e000-00007fff9acd3000', '[cow]'),
 ('00007fff9acd3000-00007fff9acd4000', '[cow]'),
 ('00007fff9acd4000-00007fff9acd5000', '[cow]'),
 ('00007fff9acd5000-00007fff9acd6000', '[cow]'),
 ('00007fff9acd6000-00007fff9ae18000', '[cow]'),
 ('00007fff9ee18000-00007fff9f000000', '[cow]'),
 ('00007fff9f000000-00007fff9fa00000', '[cow]'),
 ('00007fff9fa00000-00007fff9fc00000', '[cow]'),
 ('00007fff9fc00000-00007fff9fe00000', '[cow]'),
 ('00007fff9fe00000-00007fffa0000000', '[cow]'),
 ('00007fffa0000000-00007fffa0200000', '[cow]'),
 ('00007fffa0200000-00007fffa0400000', '[cow]'),
 ('00007fffa0400000-00007fffa0600000', '[cow]'),
 ('00007fffa0600000-00007fffa0800000', '[cow]'),
 ('00007fffa0800000-00007fffa0a00000', '[cow]'),
 ('00007fffa0a00000-00007fffa0c00000', '[cow]'),
 ('00007fffa0c00000-00007fffa0e00000', '[cow]'),
 ('00007fffa0e00000-00007fffa1000000', '[cow]'),
 ('00007fffa1000000-00007fffa1200000', '[cow]'),
 ('00007fffa1200000-00007fffa1400000', '[cow]'),
 ('00007fffa1400000-00007fffa1600000', '[cow]'),
 ('00007fffa1600000-00007fffa1800000', '[cow]'),
 ('00007fffa1800000-00007fffa1a00000', '[cow]'),
 ('00007fffa1a00000-00007fffa1c00000', '[cow]'),
 ('00007fffa1c00000-00007fffa1e00000', '[cow]'),
 ('00007fffa1e00000-00007fffa2000000', '[cow]'),
 ('00007fffa2000000-00007fffa2400000', '[cow]'),
 ('00007fffa2400000-00007fffa2600000', '[cow]'),
 ('00007fffa2600000-00007fffa2800000', '[cow]'),
 ('00007fffa2800000-00007fffa2a00000', '[cow]'),
 ('00007fffa2a00000-00007fffa2c00000', '[cow]'),
 ('00007fffa2c00000-00007fffa2e00000', '[cow]'),
 ('00007fffa2e00000-00007fffa3000000', '[cow]'),
 ('00007fffa3000000-00007fffa3200000', '[cow]'),
 ('00007fffa3200000-00007fffa3400000', '[cow]'),
 ('00007fffa3400000-00007fffa3600000', '[cow]'),
 ('00007fffa3600000-00007fffa3800000', '[cow]'),
 ('00007fffa3800000-00007fffa3a00000',
  '/private/var/db/dyld/dyld_shared_cache_x86_64h'),
 ('00007fffa3a00000-00007fffa3acf000',
  '/private/var/db/dyld/dyld_shared_cache_x86_64h'),
 ('00007fffffe00000-00007fffffe01000', '[shm]'),
 ('00007ffffff1e000-00007ffffff1f000', '[shm]')]
```
