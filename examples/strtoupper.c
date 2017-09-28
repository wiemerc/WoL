// The string needs to be defined as global *array* (not pointer), otherwise GCC
// will treat it as a constant and put it into the .rdata segment, which gets
// memory-mapped read-only by our loader and the string can therefore not be changed.
static char s[] = "hello world";

int start()
{
    char *p;
    for (p = s; *p != 0; p++) {
        if (*p >= 97 && *p <= 122)
            *p -= 32;
    }
    return 0;
}
