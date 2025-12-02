#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>

#define PAGE_SIZE 4096
#define ITER 10000
 
static int *shared_counter;    // counter at offset 0 of the page
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/*************************************** DSM ********************************************************/
#define DSM 1

static inline unsigned long now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000UL + (unsigned long)tv.tv_usec;
}

typedef struct GlobalMemory {
    long id;
    pthread_mutex_t idlock;

    struct {
        pthread_mutex_t mutex;
        pthread_cond_t  cv;
        unsigned long   counter;
        unsigned long   cycle;
    } start;

    long *transtimes;
    long *totaltimes;
    unsigned long starttime;
    unsigned long finishtime;
    unsigned long initdonetime;
} GlobalMemory;

GlobalMemory *Global;   // the global pointer

int local_threads  = 0;
int auth_thread    = 0;
int total_threads  = 0;
int dsm_active     = 0;
int server         = 0;
int done           = 0;

pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER; 

#define NUM_BARRIER_PAGES 8

int count[NUM_BARRIER_PAGES];
static void *mutex_lock_page  = NULL;
static void *mutex_unlock_page  = NULL;
static size_t page_size         = 0;
static int current_lock_page = 0;  // global page index, rotated by every thread
static int current_unlock_page = 0;  // global page index, rotated by every thread

/* call this once at program start */
void dsm_init_barrier_pages(void) {
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;

    size_t length = NUM_BARRIER_PAGES * page_size;

    mutex_lock_page = mmap(NULL, length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
            -1, 0);
    if (mutex_lock_page == MAP_FAILED) {
        fprintf(stderr, "[APP] mmap failed: %s\n", strerror(errno));
        mutex_lock_page = NULL;
        return;
    }

    mutex_unlock_page = mmap(NULL, length,
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
                          -1, 0);
    if (mutex_unlock_page == MAP_FAILED) {
        fprintf(stderr, "[APP] mmap failed: %s\n", strerror(errno));
        mutex_unlock_page = NULL;
        return;
    }

    // Touch each page so they are faulted in
    for (int i = 0; i < NUM_BARRIER_PAGES; i++) {
        volatile char *p = (volatile char *)mutex_lock_page + (size_t)i * page_size;
        volatile char *t = (volatile char *)mutex_unlock_page + (size_t)i * page_size;
        *p = 0;
        *t = 0;
    }

    FILE *f = fopen("/tmp/dsm_mutex.txt", "w");
    if (f) {
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n", mutex_lock_page, page_size, NUM_BARRIER_PAGES);
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n", mutex_unlock_page, page_size, NUM_BARRIER_PAGES);
        fclose(f);
    }

    fprintf(stderr, "[APP] lock region mapped at %p, lock: %d pages (total %zu bytes), unlock: mmap at%p,  %d pages (total %zu bytes), [/tmp/dsm_mutex.txt]\n",
        mutex_lock_page, NUM_BARRIER_PAGES, length,  mutex_unlock_page, NUM_BARRIER_PAGES, length);
}

void check_halt_file(int tid){
    printf("Thread %d: Waiting for haltcode file /tmp/haltcode to continue...\n", tid);
    fflush(stdout);
    while (access("/tmp/haltcode", F_OK) != 0) {
        // spin wait for haltcode file
    }
    printf("Thread %d: Haltcode file detected, continuing execution\n", tid);
    fflush(stdout);
}

/*************************************** DSM ********************************************************/

void *worker(void *arg) {
    struct timespec ts;
    ts.tv_sec = 0;        // seconds
    ts.tv_nsec = 5000000; // 5 ms = 5,000,000 ns
    int tid = *(int *)arg;   // thread ID passed from main
    int idx0, idx1;
    volatile unsigned char *q0, *q1;

    check_halt_file(tid);

    for (int i = 0; i < ITER; i++) {
        // Local mutex acquisition
        pthread_mutex_lock(&lock);

        // Global mutex acquisition: write to current barrier page
        idx0 = current_lock_page;
        q0 = (volatile unsigned char *)mutex_lock_page + (size_t)idx0 * page_size;
        q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

        fprintf(stderr, "[APP] thread %d wants mutex %p (index=%d)\n",
                tid, (void *)q0, idx0);

        // Advance index
        current_lock_page = (current_lock_page + 1) % NUM_BARRIER_PAGES;

        // WORK: increment shared counter
        (*shared_counter)++;
        printf("Thread %d incremented counter to %d\n", tid, *shared_counter);
        //sleep(1);

        // Global mutex release: write to next barrier page
        idx1 = current_unlock_page;
        q1 = (volatile unsigned char *)mutex_unlock_page + (size_t)idx1 * page_size;
        q1[0] = (unsigned char)(q1[0] ^ 1);

        fprintf(stderr, "[APP] thread %d released mutex %p (index=%d)\n",
                tid, (void *)q1, idx1);

        current_unlock_page = (current_unlock_page + 1) % NUM_BARRIER_PAGES;

        // Local mutex release
        pthread_mutex_unlock(&lock);
        //sleep(1);
        if (nanosleep(&ts, NULL) != 0) {
            perror("nanosleep");
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0) {
        fprintf(stderr, "num_threads must be > 0\n");
        return 1;
    }

    int thread_ids[num_threads];   // holds the IDs 0..N-1

    // Initialize DSM barrier pages (global mutex mechanism)
    dsm_init_barrier_pages();
    if (!mutex_lock_page) {
        fprintf(stderr, "Failed to initialize barrier pages\n");
        return 1;
    }

    // --- Allocate a single mmap page for the shared counter ---
    void *page = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_POPULATE | MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    FILE *f = fopen("/tmp/ranges.txt", "w");
    if (!f) {
        perror("Failed to open /tmp/ranges.txt");
        munmap(page, PAGE_SIZE);
        exit(EXIT_FAILURE);
    }

    fprintf(f, "base=%p page_size=%d num_pages=%d\n", page, PAGE_SIZE, 1);
    fclose(f);

    shared_counter = (int *)page;   // counter lives at offset 0
    *shared_counter = 0;

    pthread_t threads[num_threads];

    // --- Launch threads ---
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i;   // assign ID
        if (pthread_create(&threads[i], NULL, worker, &thread_ids[i]) != 0) {
            perror("pthread_create");
            // In a real program you’d also join already-created threads here
            munmap(page, PAGE_SIZE);
            return 1;
        }
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
