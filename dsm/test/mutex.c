#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define ITER 1000000

static int *shared_counter;    // counter at offset 0 of the page
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *worker(void *arg) {
    for (int i = 0; i < ITER; i++) {
        pthread_mutex_lock(&lock);
        (*shared_counter)++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);

    // --- Allocate a single mmap page for the shared counter ---
    void *page = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    shared_counter = (int *)page;   // counter lives at offset 0
    *shared_counter = 0;

    pthread_t threads[num_threads];

    // --- Launch threads ---
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }

    // --- Join threads ---
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // --- Print result ---
    printf("Final counter = %d (expected = %d)\n",
           *shared_counter, num_threads * ITER);

    munmap(page, PAGE_SIZE);
    return 0;
}

