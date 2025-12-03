/* 64-bit safe histogram for giant BMP files
 * Fully rewritten to support multi-GB images
 *
 * Based on Phoenix Histogram benchmark (Stanford, 2007–2009)
 */

#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>

#include "stddefines.h"   // this is already in your Phoenix tree

static inline long time_diff_us(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000L +
           (end.tv_nsec - start.tv_nsec) / 1000L;
}

#define IMG_DATA_OFFSET_POS 10
#define BITS_PER_PIXEL_POS 28

int swap = 0;      // whether to swap endian
int iterations = 0;

typedef struct {
    unsigned char *data;
    uint64_t data_pos;     // offset in bytes
    uint64_t data_len;     // length in bytes
    uint64_t red[256];
    uint64_t green[256];
    uint64_t blue[256];
} thread_arg_t;


/* endian detection */
void test_endianess() {
    unsigned int num = 0x12345678;
    char *low = (char *)(&num);
    if (*low == 0x78) {
        dprintf("No need to swap\n");
        swap = 0;
    } else if (*low == 0x12) {
        dprintf("Need to swap\n");
        swap = 1;
    } else {
        printf("Error: Invalid endian detection\n");
        exit(1);
    }
}

/* swap bytes for endian correction */
void swap_bytes(char *bytes, int num_bytes) {
    for (int i = 0; i < num_bytes/2; i++) {
        char tmp = bytes[i];
        bytes[i] = bytes[num_bytes - i - 1];
        bytes[num_bytes - i - 1] = tmp;
    }
}

/* Histogram computation for each thread */
void *calc_hist(void *arg) {
    thread_arg_t *t = (thread_arg_t *)arg;

    uint64_t *red   = t->red;
    uint64_t *green = t->green;
    uint64_t *blue  = t->blue;

    for (int it = 0; it < iterations; it++) {
        uint64_t end = t->data_pos + t->data_len;
        for (uint64_t i = t->data_pos; i < end; i += 3) {
            unsigned char b = t->data[i];
            unsigned char g = t->data[i + 1];
            unsigned char r = t->data[i + 2];

            blue[b]++;
            green[g]++;
            red[r]++;
        }
    }

    return NULL;
}


int main(int argc, char *argv[]) {

    if (argc < 4) {
        printf("USAGE: %s <bitmap filename> <num_threads> <iterations>\n", argv[0]);
        exit(1);
    }

    char *fname = argv[1];
    int num_procs = atoi(argv[2]);
    iterations = atoi(argv[3]);

    int fd;
    char *fdata;
    struct stat finfo;

    CHECK_ERROR((fd = open(fname, O_RDONLY)) < 0);
    CHECK_ERROR(fstat(fd, &finfo) < 0);

    CHECK_ERROR((fdata = mmap(0, finfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == NULL);

    if (fdata[0] != 'B' || fdata[1] != 'M') {
        printf("Not a valid BMP file\n");
        exit(1);
    }

    test_endianess();

    /* read bits-per-pixel (2 bytes) */
    uint16_t *bitsperpixel = (uint16_t *)&fdata[BITS_PER_PIXEL_POS];
    uint16_t bpp = *bitsperpixel;
    if (swap) swap_bytes((char *)&bpp, sizeof(bpp));

    if (bpp != 24) {
        printf("Only 24-bit BMP supported\n");
        exit(1);
    }

    /* read data offset (4 bytes!) */
    uint32_t data_off_raw = *(uint32_t *)&fdata[IMG_DATA_OFFSET_POS];
    if (swap) swap_bytes((char *)&data_off_raw, sizeof(data_off_raw));

    uint64_t data_offset = (uint64_t)data_off_raw;

    /* compute sizes safely */
    uint64_t filesize     = (uint64_t)finfo.st_size;
    uint64_t imgdata_bytes = filesize - data_offset;
    uint64_t num_pixels    = imgdata_bytes / 3;

    printf("This file has %" PRIu64 " bytes of image data, %" PRIu64 " pixels\n",
           imgdata_bytes, num_pixels);

    uint64_t total_pixels = num_pixels * (uint64_t)iterations;
    printf("Total pixel computation: %" PRIu64 ", iterations:%d\n",
           total_pixels, iterations);

    printf("Starting pthreads histogram\n");

    uint64_t red[256] = {0};
    uint64_t green[256] = {0};
    uint64_t blue[256] = {0};

    pthread_t *pid;
    thread_arg_t *arg;

    CHECK_ERROR((pid = malloc(sizeof(pthread_t) * num_procs)) == NULL);
    CHECK_ERROR((arg = calloc(num_procs, sizeof(thread_arg_t))) == NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

    printf("The number of processors is %d, iterations:%d\n", num_procs, iterations);

    uint64_t per_thread = num_pixels / num_procs;
    uint64_t excess     = num_pixels % num_procs;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t curr_pos = data_offset;

    for (int i = 0; i < num_procs; i++) {
        arg[i].data = (unsigned char *)fdata;

        uint64_t pixels_for_thread = per_thread;
        if (excess > 0) {
            pixels_for_thread++;
            excess--;
        }

        arg[i].data_pos = curr_pos;
        arg[i].data_len = pixels_for_thread * 3;  // bytes

        curr_pos += arg[i].data_len;

        pthread_create(&pid[i], &attr, calc_hist, &arg[i]);
    }

    for (int i = 0; i < num_procs; i++) {
        pthread_join(pid[i], NULL);
    }

    /* merge results */
    for (int t = 0; t < num_procs; t++) {
        for (int v = 0; v < 256; v++) {
            red[v]   += arg[t].red[v];
            green[v] += arg[t].green[v];
            blue[v]  += arg[t].blue[v];
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    long us = time_diff_us(t0, t1);

    /* write output */
    char outname[512];
    snprintf(outname, sizeof(outname),
             "histogram_%" PRIu64 "_check.txt",
             total_pixels);

    FILE *outf = fopen(outname, "w");
    if (!outf) {
        perror("fopen write");
        exit(1);
    }

    fprintf(outf, "Pos\tBlue\tGreen\tRed\n");
    for (int i = 0; i < 256; i++) {
        fprintf(outf, "%3d\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
                i, blue[i], green[i], red[i]);
    }
    fclose(outf);

    printf("[APP] Histogram table written to %s\n", outname);

    munmap(fdata, finfo.st_size);
    close(fd);

    pthread_attr_destroy(&attr);

    printf("Elapsed: %ld us (%.3f ms, %.6f s)\n",
           us,
           us / 1000.0,
           us / 1e6);

    return 0;
}
