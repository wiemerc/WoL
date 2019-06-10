//
// minimalistic startup code to be used with the example programs
// We use our own startup code because real startup codes do all kinds of fancy stuff, like initializing
// data structures for the C standard library. This is a problem because it would require us to implement
// (possibly quite a lot of) additional system routines. However, this also means that we cannot use a
// complete C standard library (because of the missing initialization) but have to add the code for the
// necessary routines (in our case from klibc) to the project and link it to the example programs directly.
//


int cwmain();


void start()
{
    // call cwmain()
    cwmain();
}
