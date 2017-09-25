#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


static const unsigned long PE_IMAGE_BASE = 0x00400000;


int main(int argc, char **argv)
{
    int         fd;
    struct stat sb;
    void        *ptr;

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        perror("ERROR: could not open file");
        return 1;
    }
    if (fstat(fd, &sb) == -1) {
        perror("ERROR: could not get file status");
        close(fd);
        return 1;
    }
    if ((ptr = mmap((void *) PE_IMAGE_BASE, sb.st_size, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0)) == MAP_FAILED) {
        perror("ERROR: could not memory-map file");
        close(fd);
        return 1;
    }
    
    printf("file mapped at address 0x%08x\n", (unsigned int) ptr);
    while (getchar() != EOF);
    munmap (ptr, sb.st_size);
    close (fd);
    return 0;
}
