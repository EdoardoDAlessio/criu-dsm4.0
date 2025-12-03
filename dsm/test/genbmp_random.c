#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <inttypes.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
} BITMAPFILEHEADER;

typedef struct {
    uint32_t biSize;
    int32_t  biWidth;
    int32_t  biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount;
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t  biXPelsPerMeter;
    int32_t  biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
} BITMAPINFOHEADER;
#pragma pack(pop)


typedef struct {
    int thread_id;
    int start_row;
    int end_row;
    int W;
    int H;
    int rowSize;
    unsigned char *buffer;
} thread_arg_t;


void *worker(void *arg) {
    thread_arg_t *a = (thread_arg_t*)arg;

    unsigned char *buf = a->buffer;
    int W = a->W;
    int rowSize = a->rowSize;

    // per-thread random seed
    unsigned int seed = time(NULL) ^ (a->thread_id * 7919);

    for (int y = a->start_row; y < a->end_row; y++) {
        unsigned char *row = buf + (uint64_t)y * rowSize;

        for (int x = 0; x < W; x++) {
            row[3*x+0] = rand_r(&seed) & 0xFF;  // Blue
            row[3*x+1] = rand_r(&seed) & 0xFF;  // Green
            row[3*x+2] = rand_r(&seed) & 0xFF;  // Red
        }

        // zero padding bytes
        for (int p = W*3; p < rowSize; p++)
            row[p] = 0;
    }

    return NULL;
}



int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <width> <height> <outfile.bmp> <threads>\n", argv[0]);
        return 1;
    }

    int W = atoi(argv[1]);
    int H = atoi(argv[2]);
    const char *filename = argv[3];
    int NUM_THREADS = atoi(argv[4]);

    int rowSize = (W * 3 + 3) & ~3;
    uint64_t dataSize = (uint64_t)rowSize * (uint64_t)H;

    printf("Allocating %" PRIu64 " bytes (%.2f GB)\n",
           dataSize, dataSize / (1024.0*1024.0*1024.0));

    unsigned char *buffer = malloc(dataSize);
    if (!buffer) {
        perror("malloc");
        return 1;
    }

    // Create worker threads
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    int rows_per_thread = H / NUM_THREADS;
    int extra = H % NUM_THREADS;

    int row = 0;
    for (int t = 0; t < NUM_THREADS; t++) {
        int start = row;
        int count = rows_per_thread + (extra > 0 ? 1 : 0);
        if (extra > 0) extra--;

        int end = start + count;
        row = end;

        args[t].thread_id = t;
        args[t].start_row = start;
        args[t].end_row = end;
        args[t].W = W;
        args[t].H = H;
        args[t].rowSize = rowSize;
        args[t].buffer = buffer;

        pthread_create(&threads[t], NULL, worker, &args[t]);
    }

    for (int t = 0; t < NUM_THREADS; t++)
        pthread_join(threads[t], NULL);

    // --- WRITE FILE ---
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("fopen");
        free(buffer);
        return 1;
    }

    BITMAPFILEHEADER fileHeader = {
        .bfType = 0x4D42,
        .bfSize = 54 + dataSize,
        .bfReserved1 = 0,
        .bfReserved2 = 0,
        .bfOffBits = 54
    };

    BITMAPINFOHEADER infoHeader = {
        .biSize = 40,
        .biWidth = W,
        .biHeight = H,
        .biPlanes = 1,
        .biBitCount = 24,
        .biCompression = 0,
        .biSizeImage = dataSize,
        .biXPelsPerMeter = 2835,
        .biYPelsPerMeter = 2835,
        .biClrUsed = 0,
        .biClrImportant = 0
    };

    fwrite(&fileHeader, sizeof(fileHeader), 1, f);
    fwrite(&infoHeader, sizeof(infoHeader), 1, f);
    fwrite(buffer, dataSize, 1, f);

    fclose(f);
    free(buffer);

    printf("Done.\n");
    return 0;
}
