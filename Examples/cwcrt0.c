//
// minimalistic startup code to be used with the example programs
// We use our own startup code for the two following reasons:
// (1) The calling convention for programs is different from the one on Windows (see comment in vwin.cxx)
// (2) Real startup codes do all kinds of fancy stuff, like initializing data structures for the C standard library.
//     This is a problem because it would require us to implement (possibly quite a lot of) additional system
//     routines. However, this also means that we cannot use a complete C standard library (because of the missing
//     initialization) but have to add the code for the necessary routines (in our case from klibc) to the project
//     and link it to the example programs directly.
//


int cwmain();
//int cwmain(int argc, char **argv);


void start()
{
    // push argc (D0) / argv (A0) onto stack
//    asm("move.l     A0, -(A7)\n"
//        "move.l     D0, -(A7)\n");

    // call cwmain()
    cwmain();
//    asm("jsr        _cwmain\n"
//        "add.l      #8, A7");
}
