void start()
{
    char *s = "hello world";
    char *p;
    for (p = s; *p != 0; p++) {
        if (*p >= 97 && *p <= 122)
            *p -= 32;
    }
    return;
}