Title: Gastarbeiter - Windows-Programme auf Linux ausführen - Teil 1
Category: Hacks


## Einführung

Auf den ersten Blick erscheint es sicher verrückt, ein Windows-Programm auf Linux ausführen zu wollen, also einem Windows-Programm ein Windows-Betriebssystem vorzugaukeln (Windows zu emulieren). Aber in diesem Artikel werde ich zeigen, wie man genau das machen kann, und dass es noch nicht einmal so schwierig ist - zumindest wenn man sich auf einfache Programme beschränkt. Dass das überhaupt möglich ist, und nicht nur mit einfachen Programmen, zeigt ja das Projekt [Wine](https://www.winehq.org/), und den umgekehrten Weg gehen die neueren Versionen von Windows 10 mit dem [Windows Subsystem for Linux (WSL)](https://de.wikipedia.org/wiki/Windows_Subsystem_for_Linux). Ausserdem hatte ich vor einiger Zeit einen [Emulator für AmigaOS](https://github.com/wiemerc/VADM) geschrieben, das heisst eine Software, die Programme, die für den [Commodore Amiga](https://de.wikipedia.org/wiki/Amiga) entwickelt wurden, auf Linux und macOS ausführt. Ich hatte also schon etwas Erfahrung mit der Emulation eines Betriebssystems gesammelt.
 
Abgesehen davon, dass ich sehen wollte, ob ich das wirklich hinbekomme, hat mich das Projekt auch deshalb gereizt, weil ich schon immer mal verstehen wollte, was eigentlich beim Starten eines Programmes genau passiert. Ausserdem war das Projekt eine gute (wenn auch etwas unkonventionelle) Möglichkeit, Windows besser kennenzulernen. Und in irgendwelchen Strukturen des Betriebssystems "herumzuwühlen" hat mir auch schon immer Spass gemacht - Gelegenheit dazu gab es in diesem Projekt genügend, wie wir noch sehen werden.
 
Bei dem Namen des Projekts, _Windows on Linux_ oder WoL habe ich mich übrigens von WoW inspirieren lassen, einer Komponente in den 32-Bit-Versionen von Windows, die es ermöglicht, 16-bittige Windows-Programme auszuführen, die also ein Windows 3.1 emuliert.

Bei den Programmen, die ich zum Testen von WoL verwendet habe, handelt es sich um zwei ganz einfache Programme, nämlich `strtoupper.exe`, das einen String in Grossbuchstaben umwandelt und gänzlich ohne Aufrufe des Betriebssystems auskommt, und `winhello.exe`, das den String `Hello, Windows` ausgibt. Bei beiden Programmen handelt es sich um 32-Bit-Programme.

Was ist denn nun alles notwendig, um ein Windows-Programm auf Linux auszuführen? Oder anders ausgedrückt, was sind denn die Unterschiede zwischen einem Windows- und einem Linux-Programm? Dabei gehe ich im folgenden davon aus, dass Windows und Linux beide auf der gleichen Prozessorarchitektur laufen, nämlich Intel x86-64.
 

## Emulation der API / ABI

Der erste Unterschied ist die Schnittstelle zwischen einem Programm und dem Betriebssystem, und zwar sowohl die [API](https://de.wikipedia.org/wiki/Programmierschnittstelle), also die Systemroutinen, die das Betriebssystem zur Verfügung stellt, als auch die [ABI](https://de.wikipedia.org/wiki/Binärschnittstelle), die unter anderem die Aufrufkonventionen für Funktionen und den Mechanismus für Systemaufrufe festlegt. Um also ein Windows-Programm auf Linux ausführen zu können muss die API von Windows emuliert werden, (zumindest der Teil, den das Programm verwendet), und das so, wie es die ABI vorgibt.

Was bedeutet das nun konkret? Man muss dazu wissen, dass Systemroutinen letztendlich keine normale Funktionen sind sondern einen [Systemaufruf](https://de.wikipedia.org/wiki/Systemaufruf) darstellen. Der genaue Mechanismus dafür ist abhängig vom Betriebssystem und der Prozessorarchitektur. Warum aber lassen sich Systemroutinen dann doch in Programmen wie gewöhnliche Funktionen aufrufen? Die Antwort ist, dass es für all diese Routinen sogenannte [Stubs](https://de.wikipedia.org/wiki/Stub_(Programmierung)) in einer Bibliothek gibt, die dann den eigentlichen Systemaufruf durchführen. Die Bibliothek bildet also das Bindeglied zwischen dem Betriebssystem und dem Programm. Dadurch müssen weder der Programmierer noch der Compiler den genauen Mechanismus für einen Systemaufruf kennen. Auf Linux übernimmt diese Aufgabe die C-Standardbibliothek, auf Windows die Bibliothek `KERNEL32.DLL`, die wiederum die `NTDLL.DLL` verwendet. 

Um nun die Windows API für die Testprogramme auf Linux zu emulieren habe ich eine eigene, sehr einfache `KERNEL32.DLL` geschrieben, die nur die beiden von den Testprogrammen benötigten Systemroutinen `GetStdHandle` und `WriteFile` zur Verfügung stellt. Diese DLL verwendet logischerweise nicht wie auf Windows die `NTDLL.DLL` sondern die Linux API, genauer gesagt die Funktion `write`, und ist somit das Bindeglied zwischen dem Windows-Programm und Linux.

Das folgende Bild zeigt nochmal die durchlaufenen Komponenten wenn ein Programm eine Systemroutine verwendet, links für Windows und rechts für WoL.
![Ablauf einer Systemroutine]({attach}/WoL/images/syscall.svg)
 
 Der folgende Code-Schnipsel zeigt die Implementierung der Funktion [`WriteFile`](https://github.com/wiemerc/WoL/blob/0916f43a3f538d9052ccfa71a3f4f3fce0edb801/libs/kernel32.c#L42) in dieser DLL.

    :::c
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

Zwei Dinge sind daran bemerkenswert. Erstens wirst du wahrscheinlich (zumindest auf den ersten Blick) den Aufruf der Funktion `write` vermissen, die ich gerade erwähnt hatte. Diese Funktion wird sehr wohl aufgerufen, aber nicht so, wie man das normalerweise machen würde. Der Aufruf erfolgt nämlich durch den Inline-Assembler-Block. So sieht nämlich ein Systemaufruf für Linux auf einer x86-Architektur (32 Bit) aus, und so ist er auch in der C-Standardbibliothek implementiert. Warum mache ich das so und nutze nicht einfach für meine DLL auch die C-Standardbibliothek? Aus zwei Gründen ist das nicht möglich. Es handelt sich bei meiner DLL ja um eine Bibliothek für _Windows_, und diese würde nicht gegen die C-Standardbibliothek von Linux (normalerweise die _glibc_) sondern gegen die von Windows gelinkt werden, also die `MSVCRT.DLL`. Diese wiederum stellt aber logischerweise keine Stubs für Linux-Systemroutinen zur Verfügung. Ein weiteres Problem wäre, dass die `MSVCRT.DLL` oder der Startup-Code, der die C-Standardbibliothek initialisiert und der ebenfalls zu dem Programm gelinkt werden würde, weitere Systemroutinen aus der echten `KERNEL32.DLL` verwenden.

Die zweite Besonderheit ist, dass die Funktion mit der Aufrufkonvention `__stdcall` definiert wird. Das ist die Aufrufkonvention, die von den Windows-API-Funktionen benutzt wird und bedeutet, dass die aufgerufene Funktion (also in diesem Fall `WriteFile`) vor der Rückkehr die Parameter vom Stack entfernt.


## Laden des Programms

Der zweite Unterschied zwischen einem Windows- und einem Linux-Programm ist, dass Windows und Linux unterschiedliche Dateiformate für Programme nutzen, Windows verwendet die Formate PE (32 Bit) bzw. PE+ (64 Bit), Linux verwendet ELF. Der Loader von Linux, also die Komponente im Betriebssystem, die für das Laden von Programmen zuständig ist, kann daher Windows-Programme gar nicht laden. So einen Loader musste ich also selber implementieren. Das stellte sich allerdings als relativ einfach heraus, da PE so entworfen wurde , dass die ganze Programmdatei (das _Image_) mit [Memory-mapped IO](https://en.wikipedia.org/wiki/Memory-mapped_I/O) an einem Stück in den Speicher geladen werden kann. Das bedeutet, dass die bei der Ausführung des Programms verwendeten Datenstrukturen, wie die Import- und Export-Tabellen, bereits in der Datei in sehr ähnlicher Form vorhanden sind und nicht erst beim Laden der Datei im Speicher erstellt werden müssen (im Gegensatz zu dem Vorgängerformat NE, das von den 16-Bit-Windows-Versionen verwendet wurde).

Eine sehr gute Beschreibung des PE-Formats und der zugrunde liegenden Konzepte bietet der Artikel [Peering Inside the PE](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)). Deswegen werde ich in diesem Artikel auch nicht auf die Details des Formats eingehen. Weitergehende Informationen findet man auch in der offiziellen PE-Spezifikation von Microsoft. [Hier](https://drive.google.com/file/d/0B3_wGJkuWLytbnIxY1J5WUs4MEk/view) findet man ein hilfreiches Übersichtsbild, das die einzelnen Datenstrukturen und ihre Beziehungen untereinander darstellt. Die von PE verwendeten Datenstrukturen sind bei Windows in der Header-Datei `winnt.h` definiert. WoL verwendet allerdings nicht direkt diese Header-Datei sondern die benötigten Strukturen sind, basierend auf den Definitionen in `winnt.h`, in der Datei `wol.h` [definiert](https://github.com/wiemerc/WoL/blob/0916f43a3f538d9052ccfa71a3f4f3fce0edb801/wol.h#L11). Der Grund dafür ist, dass die Datei `winnt.h` eine Reihe von MSVC-spezifischen Konstrukten enthält, mit denen weder GCC noch Clang zurechtkommen.

Sofern [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) nicht aktiviert ist wird bei PE und PE+ davon ausgegangen, dass das Programm immer an die gleiche Adresse (0x00400000) geladen wird, deswegen enthält die Programmdatei nicht zwingend [Relocation](https://en.wikipedia.org/wiki/Relocation_(computing))-Informationen. Bei 64-Bit-Prozessen unter Linux ist die Adresse 0x00400000 allerdings schon belegt, sie wird standardmässig auch von Linux als Basisadresse von Programmen verwendet. Damit sie für das Windows-Programm verwendet werden kann musste ich deshalb beim Linken von WoL eine andere Startadresse für das Text-Segment angeben, ich habe mich für die Adresse 0x10400000 entschieden (mit der Option `-Wl,-Ttext,0x10400000`).

Es gibt je nach verwendetem Compiler / Linker unterschiedliche Ausprägungen des Formats, so erzeugt MinGW zum Beispiel im Gegensatz zum MSVC separate Segmente für die Import- und Export-Tabellen (`.idata` und `.edata`), mit dem MSVC erzeugte Programme enthalten dafür standardmässig (wenn man nicht die Linker-Option `/FIXED` angibt) doch Relocation-Informationen (in dem Segment `.reloc`).

Das Laden des Programms und der verwendeten DLL(s) ist in WoL in der Funktion [`load_image`](https://github.com/wiemerc/WoL/blob/0916f43a3f538d9052ccfa71a3f4f3fce0edb801/wol.c#L63) implementiert, wobei ich mich auf PE, also auf 32-Bit-Programme, beschränkt habe. Folgende Schritte sind dafür im einzelnen notwendig.

1. Komplette Programmdatei mit Memory-mapped IO (mit der Systemroutine `mmap`) in den Speicher laden (an beliebige Adresse)

2. Header lesen und überprüfen  
    Interessanterweise beginnt jede Programmdatei im PE-Format mit einem kleinen MS-DOS-Programm, das, wenn man es unter MS-DOS ausführte, die Fehlermeldung "This program cannot be run in DOS mode" ausgeben würde. Wie relevant das im Jahr 2019 noch ist sei mal dahingestellt... Dieses "Feature" hat aber zur Folge, dass eine Programmdatei im PE-Format mit einem MS-DOS-Header beginnt, gefolgt von zwei Windows-spezifischen Headern (die als NT-Header bezeichnet werden weil das PE-Format 1993 mit Windows NT eingeführt wurde). Die relevanten Informationen in den Headern sind hierbei der Zeiger auf die Windows-Header im MS-DOS-Header sowie die Basisadresse des Programms und die Anzahl der Segmente in der Datei in den Windows-Headern. Sowohl der MS-DOS- als auch die Windows-Header enthalten eine Signatur, die ich in diesem Schritt zusammen mit der Grösse der Header überprüfe.

3. In diesem Schritt geht es jetzt tatsächlich um das eigentliche Programm beziehungsweise um die einzelnen Segmente (Code, Daten und so weiter). Es gibt in PE eine Segment-Tabelle, über die ich iteriere und für jedes Segment folgendes mache:
    * Mapping für das Segment an der vorgegebenen Adresse  = die relative virtuelle Adresse (RVA) + Basisadresse des Programms (normalerweise 0x00400000) erzeugen  
        Das mache ich wieder mit `mmap` mit den Flags `MAP_FIXED`, um das Mapping an der vorgegebenen Adresse zu erzwingen und `MAP_ANON` weil es sich um ein anonymes Mapping ohne zugrunde liegende Datei handelt. Du fragst dich jetzt vielleicht warum man nicht einfach die gesamte Datei an die Basisadresse laden kann. Der Grund ist, dass sich die Offsets der Segmente in der Datei von den RVAs, also den virtuellen Adressen relativ zur Basisadresse, unterscheiden (die Offsets sind im Gegensatz zu den RVAs nicht an Seitengrenzen ausgerichtet und die Segmente damit in der Datei dichter gepackt als im Adressraum um Platz zu sparen).
    * Daten aus der Datei in den gemappten Speicherbereich kopieren  
        Weil die Offsets wie gerade erwähnt (normalerweise) nicht an Seitengrenzen ausgerichtet sind kann man ebenfalls nicht einfach die Segmente aus der Datei direkt mappen (der Offset für `mmap` muss ein Vielfaches der Seitengrösse sein und `mmap` ignoriert auch die mit `lseek` gesetzte Position in der Datei).
    * Berechtigungen je nach Typ des Segments setzen (Das Code-Segment muss natürlich ausführbar sein, das Daten-Segment dafür beschreibbar und so weiter)

4. Import-Tabelle bearbeiten (siehe auch den Abschnitt [PE File Imports](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-imports) in _Peering Inside the PE_)  
    Die Import-Tabelle besteht aus einer Liste der von dem Programm verwendeten DLLs (Liste von `IMAGE_IMPORT_DESCRIPTOR`-Strukturen) und jeweils einer Liste der aus der DLL verwendeten Funktionen (Liste von `IMAGE_THUNK_DATA`-Unions). Im Orginalzustand (also so wie sie in der Programmdatei abgelegt ist) besteht die Funktionsliste aus RVAs (das Feld `AddressOfData` der Union), die jeweils auf eine weitere Datenstruktur (`IMAGE_IMPORT_BY_NAME`) verweisen, die den Namen der Funktion enthält. Diese Liste wird jedoch auch vom Programmcode als Sprungtabelle benutzt. Das bedeutet, dass der Aufruf einer Funktion einer DLL im Programmcode als indirekter Sprung an die in der Funktionsliste der DLL angegebene Adresse (das Feld `Function` der Union) implementiert ist. Deshalb müssen die RVAs durch Zeiger auf die eigentlichen Funktionen ersetzt werden bevor das Programm ausgeführt werden kann, was jedoch einfacher ist als wenn man die Sprungziele direkt im Code patchen müsste. Zuvor muss / müssen natürlich die verwendete(n) DLL(s) durch einen rekursiven Aufruf von `load_image` geladen werden. Dieser Aufruf gibt die Namen und die zugehörigen Adressen der von der DLL exportierten Funktionen zurück, die ich dann zum Patchen der Import-Tabelle verwende (siehe auch den Abschnitt [PE File Exports](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-exports) in _Peering Inside the PE_).


## Ausführen des Programms

Man sollte meinen, das Ausführen des Programms, nachdem es wie oben beschrieben in den Speicher geladen wurde, wäre trivial - einfach zu der Startadresse des Code-Segments springen. Allerdings gibt es da bei WoL eine Schwierigkeit. WoL ist ja ein 64-Bit-Programm, die Testprogramme, die ich ausführen wollte, sind (zumindest momentan) noch 32-Bit-Programme. Nun ist es aber so, dass das Ausführen von 32-Bit-Code in einem 64-Bit-Prozess standardmässig nicht funktioniert (weder auf Linux noch auf Windows). Das liegt daran, dass sich anhand der Codierung der Instruktionen nicht eindeutig sagen lässt, ob es sich bei den Instruktionen um 32-bittigen oder 64-bittigen Code handelt. Das muss man dem Prozessor explizit mitteilen. Das geschieht über den [Segment-Deskriptor](https://en.wikipedia.org/wiki/Segment_descriptor) für das Code-Segment (also der Deskriptor, der über den Selektor im Register CS referenziert wird). Wenn in diesem Deskriptor das L-Bit gesetzt ist, wird der sogenannte [Long Mode](https://en.wikipedia.org/wiki/X86-64#Operating_modes) aktiviert und der Code wird vom Prozessor als 64-Bit-Code interpretiert. Genau so einen Deskriptor mit gesetztem L-Bit verwenden natürlich 64-Bit-Programme (mit dem Selektor 0x33). Allerdings fand ich nach einiger Recherche heraus, dass es sowohl bei Linux als auch bei Windows noch einen zweiten Deskriptor gibt, der das L-Bit nicht gesetzt hat (mit dem Selektor 0x23). Beide Betriebssysteme bieten also eine (wenn auch undokumentierte) Möglichkeit innerhalb eines Prozesses zwischen 32- und 64-Bit-Code hin und her zu wechseln. Dazu muss man "nur" den Code mit einen sogenannten _Far Call_ (also eine CALL-Instruktion, die neben der Zieladresse auch einen Segmentselektor verwendet) mit dem entsprechenden Selektor aufrufen und am Ende mit einem _Far Return_, wieder mit dem entsprechenden Selektor, zurückspringen.

Ganz so einfach ist es dann in der Praxis doch nicht, es gibt noch ein paar weitere Dinge zu beachten (siehe auch [hier](https://stackoverflow.com/a/32384358) und [hier](https://stackoverflow.com/a/41922752)). Im Detail sieht die ganze [Prozedur](https://github.com/wiemerc/WoL/blob/0916f43a3f538d9052ccfa71a3f4f3fce0edb801/thunk.s#L2) (die man auch als [Thunk](https://en.wikipedia.org/wiki/Thunk) oder [Trampolin](https://en.wikipedia.org/wiki/Trampoline_(computing)) bezeichnen kann) dann so aus:

    :::nasm
    .code64
    entry_point_thunk:
    push    rbp                         ; save other registers
    push    rbx
    push    r12
    mov     r12, rsp                    ; save RSP
    push    offset l_entry              ; push address of 32-bit code as qword
    mov     dword ptr [rsp + 4], 0x23   ; overwrite the high dword with the segment selector
    retf                                ; "return" to 32-bit code

    l_entry:
    .code32
    mov     esp, esi                    ; load new stack address (2nd argument - stack_ptr)
    push    ss                          ; set DS and ES to the value of SS
    pop     ds
    push    ss
    pop     es
    call    edi                         ; call entry point of Windows program passed as 1st argument (entry_point)
    push    0x0                         ; set DS back to 0
    pop     ds
    push    0x33                        ; push segment selector and address of 64-bit code
    push    offset l_return
    retf                                ; "return" to 64-bit code

    l_return:
    .code64
    mov     rsp, r12                    ; restore RSP
    pop     r12                         ; restore other registers
    pop     rbx
    pop     rbp
    ret                                 ; return to main()

Vom Hauptprogramm aufgerufen wird diese Routine mit `entry_point_thunk(<real entry point>, <new stack pointer>)`. Auf den ersten Blick wirst du wahrscheinlich in dem Code den erwähnten Far Call vermissen. Stattdessen verwende ich sowohl für den Aufruf des 32-Bit-Codes als auch für die Rückkehr zum 64-Bit-Code einen Far Return (die Instruktion RETF). Das mache ich weil von einem Far Call ja die Rücksprungadresse und der Segmentselektor auf dem Stack abgelegt werden, die ich dann erstmal wieder vom Stack entfernen müsste. Mit einem Far Return spare ich mir das, abgeschaut habe ich mir diesen Trick [hier](http://blog.rewolf.pl/blog/?p=102).

Drei weitere Dinge sollte ich noch erwähnen. Erstens muss man für den 32-Bit-Code einen separaten Stack verwenden, der in den unteren 4GB des 64-Bit-Adressraums liegen muss, so dass er von dem 32-Bit-Code adressiert werden kann. Der vom Betriebssystem bereitgestellte Stack liegt an einer höheren Adresse und ist somit ungeeignet (mal abgesehen davon, dass es sowieso sinnvoll ist, für das Windows-Programm einen eigenen Stack zu verwenden). Für diesen Stack wird in `load_image` ein anonymes Mapping an der Adresse 0xff000000 mit einer Grösse von einem Megabyte angelegt, diese Adresse plus die Grösse, also 0xff001000, wird dann der obigen Routine als neuer Wert für den Stack Pointer übergeben (weil der Stack ja von oben nach unten wächst).

Zweitens müssen vor dem Eintritt in die 32-Bit-Welt einige Register gesichert werden. Zum einen sind das die Register RBP und RBX. Das sind zwar 64-Bit-Register, aber die unteren Hälften, nämlich EBP und EBX, könnten auch von 32-bittigem Code genutzt werden. Was ist dann mit den anderen Registern, für die es auch ein 32-Bit-Äquivalent gibt, wie RAX, RSI, RDI und so weiter? Deren Wert muss laut der [ABI](https://stackoverflow.com/a/18024743) für x86-64 bei einem Funktionsaufruf nicht erhalten bleiben. Zum anderen muss natürlich RSP gesichert werden weil ich ja ESP ein paar Zeilen später auf einen neuen Wert setze (um den separaten Stack zu verwenden). Logischerweise kann man RSP nicht auf dem Stack sichern (das Problem mit der Henne und dem Ei...) sondern muss einen anderen Speicherbereich (mit einer bekannten Adresse) oder ein Register dafür nutzen. Ich entschied mich für das Register R12. Das ist nämlich das erste Register, das nicht von 32-Bit-Code genutzt werden kann und dessen Wert bei einem Funktionsaufruf im 64-Bit-Code erhalten bleibt (ebenfalls in der ABI definiert). Welcher 64-Bit-Code, wirst du dich jetzt vielleicht fragen. Das Windows-Programm ist doch ein 32-Bit-Programm. Das stimmt, aber dieses Programm nutzt meine Version der `KERNEL32.DLL`. Die ist auch immer noch 32-bittig, dort wird aber die Systemroutine `write` aufgerufen und dadurch landen wir schlussendlich in dem 64-bittigen Kernel von Linux.

Drittens benötigt 32-bittiger Code im Gegensatz zu 64-bittigem den Segmentselektor 0x2b in den Registern DS und ES, also für Datenzugriffe auf den Hauptspeicher (den Grund dafür kenne ich nicht). Das ist der gleiche Selektor, der sowohl im 32- als auch im 64-Bit-Mode für SS, also für Stack-Zugriffe, verwendet wird. Deswegen kopiere ich einfach den Wert von SS nach DS und ES.

Auf Windows wird das Ausführen von 64-Bit-Code in einem 32-Bit-Prozess übrigens auch als _Heaven's Gate_ bezeichnet (und wird unter anderem von [WoW64](https://en.wikipedia.org/wiki/WoW64) genutzt). Ich weiss nicht, ob die obige Prozedur dann ein _Hell's Gate_ darstellt ;-)


## Demo des Programms

So sieht es aus wenn man eines der Testprogramme mit WoL auf einem Linux-System startet (mit aktivierten Debug-Ausgaben):

    :::text
    $ uname -a
    Linux debian 4.9.0-7-amd64 #1 SMP Debian 4.9.110-3+deb9u2 (2018-08-13) x86_64 GNU/Linux
    $
    $ file ./wol
    ./wol: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=61d2e70733b0209971185d83ce6d9a1e21c5d732, not stripped
    $
    $ file examples/winhello.exe libs/kernel32.dll
    examples/winhello.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
    libs/kernel32.dll:     PE32 executable (DLL) (console) Intel 80386 (stripped to external PDB), for MS Windows
    $
    $ ./wol examples/winhello.exe
    INFO:  loading program examples/winhello.exe
    INFO:  mapping file examples/winhello.exe into memory
    DEBUG: image mapped at address 0x7f845bfda000
    DEBUG: number of sections: 3
    DEBUG: image base address: 0x00400000
    INFO:  loading sections
    DEBUG: section .text at offset 0x00000200, 92 / 512 (virtual / on disk) bytes large, will be mapped at 0x00401000
    DEBUG: section .rdata at offset 0x00000400, 48 / 512 (virtual / on disk) bytes large, will be mapped at 0x00402000
    DEBUG: section .idata at offset 0x00000600, 116 / 512 (virtual / on disk) bytes large, will be mapped at 0x00403000
    INFO:  loading DLL kernel32.dll used by this image
    INFO:  mapping file libs/kernel32.dll into memory
    DEBUG: image mapped at address 0x7f845bfd9000
    DEBUG: number of sections: 4
    DEBUG: image base address: 0x68480000
    INFO:  loading sections
    DEBUG: section .text at offset 0x00000400, 144 / 512 (virtual / on disk) bytes large, will be mapped at 0x68481000
    DEBUG: section .rdata at offset 0x00000600, 28 / 512 (virtual / on disk) bytes large, will be mapped at 0x68482000
    DEBUG: section .edata at offset 0x00000800, 101 / 512 (virtual / on disk) bytes large, will be mapped at 0x68483000
    DEBUG: section .idata at offset 0x00000a00, 20 / 512 (virtual / on disk) bytes large, will be mapped at 0x68484000
    DEBUG: functions exported by this DLL:
    DEBUG: GetStdHandle at address 0x68481006
    DEBUG: WriteFile at address 0x68481039
    INFO:  patching addresses of imported functions into the Import Address Table (IAT)
    DEBUG: patched function GetStdHandle with address 0x68481006
    DEBUG: patched function WriteFile with address 0x68481039
    INFO:  loaded program successfully, entry point = 0x401000
    INFO:  running program...

    >>>>>>>>>>>>>>>>>>>>>>>>
    Hello, Windows
    <<<<<<<<<<<<<<<<<<<<<<<<

    INFO:  exit code = 1

Das nachfolgende Bild zeigt das Speicherlayout von WoL während es `winhello.exe` ausführt.
![Speicherlayout von WoL]({attach}/WoL/images/memmap.svg)


## Noch ein paar Anmerkungen

### Handler für SIGSEGV

Es handelt sich bei diesem Projekt ja um einen Proof-of-Concept und daher hatte ich nicht den Anspruch, besonders robusten und sicheren Code zu schreiben. Trotzdem wollte ich nicht blindlings darauf vertrauen, dass die zu ladende Programmdatei korrekt ist. Da die Programmdatei mit Memory-mapped IO gelesen wird könnte eine fehlerhafte Datei zu ungültigen Speicherzugriffen führen. Um nun aber nicht bei jedem Speicherzugriff die Adresse, auf die zugegriffen wird, überprüfen zu müssen habe ich zu einem Trick gegriffen. Am Anfang der Funktion `load_image` installiere ich einen Handler für das Signal _SIGSEGV_ (also das Signal, das bei einem ungültigen Speicherzugriff an den Prozess gesendet wird). Dieser Handler gibt einfach eine Fehlermeldung aus und beendet das Programm. Am Ende der Funktion wird dieser Handler wieder entfernt. Zusätzlich überprüfe ich dann doch noch an einigen Stellen, ob die Grösse von bestimmten Datenstrukturen (zum Beispiel die Datei-Header) korrekt ist und ob Zeiger auf Adressen innerhalb der in den Speicher gelesenen Datei zeigen.


### Bauen der DLL und der Testprogramme mit dem Microsoft Compiler

Obwohl ich beim Entwickeln der Einfachheit halber MinGW verwendet habe können die Testprogramme auch mit dem Microsoft Compiler (MSVC) übersetzt werden. Das sind die Befehle dafür, die man am besten in einem Visual-Studio-Terminal (auf meiner Windows-10-Installation _x86 Native Tools Command Prompt for VS 2017_) ausführt:

    cl strtoupper.c /link /entry:start /subsystem:console /out:strtoupper.exe.msvc
    cl winhello.c /link /entry:start /subsystem:console kernel32.lib /out:winhello.exe.msvc


Damit bin ich am Ende des ersten Teils des Artikels angelangt. Ich hoffe, ich konnte einen Teil der vielen Dinge, die ich beim Schreiben von WoL und dieses Artikels gelernt habe, weitergeben. Im zweiten Teil werde ich zeigen was, was man tun muss wenn man ein Windows-Programm an eine andere als die vorgegebene Adresse laden will. Wir werden uns also mit den schon erwähnten Relocations befassen. Ausserdem werde ich WoL eine weitere Windows-Besonderheit beibringen, nämlich das sogenannte [Structured Exception Handling](https://docs.microsoft.com/de-de/cpp/cpp/structured-exception-handling-c-cpp?view=vs-2019).

Der vollständige Quellcode zu diesem Artikel findet sich auf [GitHub](https://github.com/wiemerc/WoL.git) und steht unter der BSD-Lizenz.