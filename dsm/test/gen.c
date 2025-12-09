#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr,"usage: gen <file> <GB>\n"); return 1; }

    const char *out = argv[1];
    long long gb = atoll(argv[2]);
    long long bytes = gb * 1024LL * 1024LL * 1024LL;

    FILE *f = fopen(out, "wb");
    if (!f) { perror("fopen"); return 1; }

    const size_t CHUNK = 1<<20;         // 1 MB
    static unsigned char buf[1<<20];

    for (size_t i = 0; i < CHUNK; i += 2) {
        buf[i]   = rand() & 0xFF;       // x
        buf[i+1] = rand() & 0xFF;       // y
    }

    while (bytes > 0) {
        size_t w = bytes > CHUNK ? CHUNK : bytes;
        fwrite(buf, 1, w, f);
        bytes -= w;
    }

    fclose(f);
    return 0;
}

