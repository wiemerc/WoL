# Gastarbeiter Teil 1 - Windows-Programme auf Linux ausführen

## Einführung

Auf den ersten Blick erscheint es sicher verru"ckt, ein Windows-Programm auf Linux ausfu"hren zu wollen, also einem Windows-Programm ein Windows-Betriebssystem vorzugauckeln (Windows zu emulieren). Aber in diesem Artikel werde ich zeigen, wie man genau das machen kann, und dass es noch nicht einmal so schwierig ist - zumindest wenn man sich auf einfache Programme beschra"nkt. Das es u"berhaupt mo"glich ist, und nicht nur mit einfachen Programmen, zeigt ja das Projekt [Wine](https://www.winehq.org/), und den umgekehrten Weg gehen die neueren Versionen von Windows 10 mit dem [Windows Subsystem for Linux (WSL)](https://de.wikipedia.org/wiki/Windows_Subsystem_for_Linux). Ausserdem hatte ich vor einiger Zeit einen [Emulator fu"r AmigaOS](https://github.com/wiemerc/VADM) geschrieben, das heisst eine Software, die Programme, die fu"r den Commodore Amiga entwickelt wurden, auf Linux und macOS ausfu"hrt. Ich hatte also schon gewisse Erfahrung mit der Emulation eines Betriebssystems gesammelt.
 
Abgesehen davon, dass ich sehen wollte, ob ich das wirklich hinbekomme, hat mich das Projekt auch deshalb gereizt, weil ich schon immer mal verstehen wollte, was eigentlich beim Starten eines Programmes genau passiert. Ausserdem war das Projekt eine gute (wenn auch etwas unkonventionelle) Möglichkeit, Windows besser kennenzulernen. Und in irgendwelchen Strukturen des Betriebssystems "herumzuwühlen" hat mir auch schon immer Spass gemacht - Gelegenheit dazu gab es in diesem Projekt genügend, wie wir noch sehen werden.
 
Bei dem Namen _Windows on Linux_ oder WoL habe ich mich übrigens von WoW inspirieren lassen, einer Komponente in den 32-Bit-Versionen von Windows, die es ermöglicht, 16-bittige Windows-Programme auszuführen, die also ein Windows 3.1 emuliert.

Was ist denn nun alles notwendig, um ein Windows-Programm auf Linux auszufu"hren? Oder anders ausgedru"ckt, was sind denn die Unterschiede zwischen einem Windows- und einem Linux-Programm? Dabei gehe ich davon aus, Windows und Linux beide auf der gleichen Prozessorarchitektur laufen, nämlich Intel x86.
 

## Emulation der API / ABI

Zum einen ist die Schnittstelle zwischen einem Programm und dem Betriebssystem unterschiedlich, und zwar sowohl die API, die Systemroutinen, die das Betriebssystem zur Verfügung stellt, als auch die ABI, die unter anderem die Aufrufkonventionen für Funktionen und den Mechanismus für Systemaufrufe festlegt. Um also ein Windows-Programm auf Linux ausfu"hren zu ko"nnen muss die API von Windows emuliert werden, (zumindest der Teil, den das Programm verwendet), und das so, wie es die ABI vorgibt. 

Was bedeutet das nun konkret? Man muss dazu wissen, das Systemroutinen letztendlich keine normale Funktionen sind sondern einen [Systemaufruf](https://de.wikipedia.org/wiki/Systemaufruf) darstellen. Der genaue Mechanismus dafür ist abhängig vom Betriebssystem und der Prozessorarchitektur. Warum aber lassen sich Systemroutinen dann doch in Programmen wie gewöhnliche Funktionen aufrufen? Die Antwort ist, dass es für all diese Routinen sogenannte [Stubs](https://de.wikipedia.org/wiki/Stub_(Programmierung)) in einer Bibliothek gibt, diese dann den eigentlichen Systemaufruf durchführen. Die Bibliothek bildet also das Bindeglied zwischen dem Betriebssystem und dem Programm. Dadurch müssen weder der Programmierer noch der Compiler den genauen Mechanismus für einen Systemaufruf kennen. Auf Linux übernimmt diese Aufgabe die C-Standardbibliothek, auf Windows die Bibliothek `KERNEL32.DLL`, die wiederum die `NTDLL.DLL` verwendet. 

Um nun die Windows API für das Beispielprogramm auf Linux zu emulieren habe ich eine eigene sehr einfache `KERNEL32.DLL` geschrieben habe, die nur die beiden vom Beispielprogramm benötigten Systemroutinen `GetStdHandle` und `WriteFile` zur Verfügung stellt. Diese DLL verwendet logischerweise nicht wie auf Windows die `NTDLL.DLL` sondern die Linux API, genauer gesagt die Funktion `write`, und ist somit das Bindeglied zwischen dem Windows-Programm und Linux.

Das folgende Diagramm zeigt nochmal die durchlaufenen Komponenten wenn ein Programm eine Systemroutine verwendet, links für Windows und rechts für WoL.
 
Windows: Kernel <-> Native API (NTDLL.DLL) <-> Windows API (KERNEL32.DLL) <-> Programm
WoL: Kernel <-> Linux API <-> eigene KERNEL32.DLL <-> Programm

 Der folgende Code-Schnippsel zeigt die Implementierung der Funktion `WriteFile` in dieser DLL.

 ```
 bool __stdcall WriteFile(
    HANDLE   hFile,
    void     *lpBuffer,
    uint32_t nNumberOfBytesToWrite,
    uint32_t *lpNumberOfBytesWritten,
    void     *lpOverlapped
)
{
    int32_t nbytes_written = 0;

    asm("movl   $4, %eax\n"         // system call number = sys_write
        "movl   8(%ebp), %ebx\n"    // hFile
        "movl   12(%ebp), %ecx\n"   // lpBuffer
        "movl   16(%ebp), %edx\n"   // nNumberOfBytesToWrite
        "int    $0x80\n"            // jump to kernel
        "movl   %eax, -4(%ebp)\n"   // store return value in nbytes_written
    );
    if (nbytes_written == -1) {
        *lpNumberOfBytesWritten = 0;
        return false;
    }
    else {
        *lpNumberOfBytesWritten = (uint32_t) nbytes_written;
        return true;
    }
}
```

Zwei Dinge sind daran bemerkenswert. Erstens wirst du wahrscheinlich (zumindest auf den ersten Blick) den Aufruf der Funktion `write` vermissen, die ich gerade erwähnt hatte. Diese Funktion wird sehr wohl aufgerufen, aber nicht so, wie man das normalerweise machen würde. Der Aufruf erfolgt nämlich durch den Inline-Assembler-Block. So sieht nämlich ein Systemaufruf für Linux auf einer x86-Architektur (32 Bit) aus, und so ist er auch in der C-Standardbibliothek implementiert. Warum mache ich das so und nutze nicht einfach für meine DLL auch die C-Standardbibliothek? Aus zwei Gründen ist das nicht möglich. Es handelt sich bei der DLL ja um eine Bibliothek für _Windows_ (übersetzt mit dem C-Compiler von Microsoft), und diese würde nicht gegen die C-Standardbibliothek von Linux (normalerweise die glibc) sondern gegen die von Windows gelinkt werden, also die `MSVCRT.DLL`. Diese wiederum stellt aber logischerweise keine Stubs für Linux-Systemroutinen zur Verfügung. Ein weiteres Problem wäre, dass die `MSVCRT.DLL` oder der Startup-Code, der die C-Standardbibliothek initialisiert und der ebenfalls zu dem Programm gelinkt werden würde, weitere Systemroutinen aus der echten `KERNEL32.DLL` verwenden.

Die zweite Besonderheit ist, dass die Funktion mit der Aufrufkonvention `__stdcall` definiert wird. Das ist die Aufrufkonvention, die von den Windows-API-Funktionen benutzt wird und bedeutet, dass die aufgerufene Funktion (also in diesem Fall `WriteFile`) vor der Rückkehr die Parameter vom Stack entfernt.


## PE / PE+

Zum anderen nutzen Windows und Linux unterschiedliche Dateiformate fu"r Programme, Windows verwendet die Formate PE bzw. PE+, Linux verwendet ELF. Der Loader von Linux, also die Komponente im Betriebssystem, die fu"r das Laden von Programmen zusta"ndig ist, kann daher Windows-Programme gar nicht laden. Das musste ich daher selber implementieren.

Gute Beschreibung des PE-Formats: _Peering Inside the PE_ und die offizielle PE-Spezifikation von Microsoft

PE wurde so entworfen, dass das ganze Executable am Stück in den Speicher geladen werden kann (mit Memory-mapped IO) => `mmap` unter Unix

Es wird davon ausgegangen, dass das Executable immer an der gleichen Adresse (0x00400000) geladen wird, deswegen gibt es keine Relocation-Informationen => Flag `MAP_FIXED`. `mmap` mit `MAP_FIXED` funktioniert nur mit 32-Bit Executables (Option `-m32`) bzw. Prozessen. Bei 64-Bit-Prozessen sind unter macOS die unteren 4GB des Adressraums für den Kernel reserviert. Bei 64-Bit-Prozessen unter Linux ist die Adresse 0x00400000 frei, sie wird standardmässig auch von ELF Executables verwendet. Damit sie für das Windows-Programm verwendet werden kann muss man allerdings beim Linken von WINONUX andere Startadressen für die Segmente angeben (zumindest für das Text-Segment).


## Ausführen von 32-Bit-Code in einem 64-Bit-Prozess

Das Ausführen von 32-Bit-Code in einem 64-Bit-Prozess funktioniert standardmässig nicht - siehe <https://stackoverflow.com/a/32384358>


## Programmstruktur

### Laden des Programms und der DLL

### Einrichten des Stacks

### Ausführen des Programms


## Sonstiges

### Speicherlayout 32 / 64 Bit

#### 32 Bits

Der Quellcode zu diesem Artikel findet sich auf [GitHub]() und steht unter der BSD-Lizenz.
