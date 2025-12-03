#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// -----------------------------------------------------------------------------
// GLOBAL MEMORY + DSM BARRIER (identical to histogram-dsm.c)
// -----------------------------------------------------------------------------
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cv;
    unsigned long   counter;
    unsigned long   cycle;
} start_barrier_t;

typedef struct GlobalMemory {
    start_barrier_t start;
    unsigned long starttime;
    unsigned long finishtime;
} GlobalMemory;

GlobalMemory *Global;

// For splash_barrier
static inline unsigned long now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000UL + (unsigned long)tv.tv_usec;
}

#if 1
void splash_barrier(GlobalMemory *Global, int P, int tid) {
    unsigned long Error, Cycle;
    long Cancel, Temp;

    Error = pthread_mutex_lock(&(Global->start).mutex);
    if (Error != 0) {
        fprintf(stderr, "Barrier mutex lock failed\n");
        exit(1);
    }

    Cycle = (Global->start).cycle;
    if (++(Global->start).counter != P) {
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &Cancel);
        while (Cycle == (Global->start).cycle)
            pthread_cond_wait(&(Global->start).cv, &(Global->start).mutex);
        pthread_setcancelstate(Cancel, &Temp);
    } else {
        (Global->start).cycle ^= 1;
        (Global->start).counter = 0;
        pthread_cond_broadcast(&(Global->start).cv);
    }

    pthread_mutex_unlock(&(Global->start).mutex);
}
#endif

// -----------------------------------------------------------------------------
// DSM barrier pages (8 pages exactly like histogram)
// -----------------------------------------------------------------------------
#define NUM_BARRIER_PAGES 8

static void *barrier_region = NULL;
static size_t page_size = 0;
static int current_barrier_index = 0;

void dsm_init_barrier_pages(void) {
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = PAGE_SIZE;

    size_t length = NUM_BARRIER_PAGES * page_size;

    barrier_region = mmap(NULL, length,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                          -1, 0);
    if (barrier_region == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        exit(1);
    }

    for (int i = 0; i < NUM_BARRIER_PAGES; i++) {
        volatile char *p = (volatile char*)barrier_region + i * page_size;
        p[0] = 0;
    }

    FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "w");
    if (f) {
        fprintf(f,"base=%p page_size=%zu num_pages=%d\n",
                barrier_region, page_size, NUM_BARRIER_PAGES);
        fclose(f);
    }

    fprintf(stderr," DSM barrier region at %p (%d pages)\n",
            barrier_region, NUM_BARRIER_PAGES);
}

// -----------------------------------------------------------------------------
// Local region used for trigger tests (the <num_pages> pages)
// -----------------------------------------------------------------------------
static void *region = NULL;
int num_threads = 0;
int num_pages   = 0;

// -----------------------------------------------------------------------------
// THREAD ARGS
// -----------------------------------------------------------------------------
typedef struct {
    int tid;
    int nthreads;
} thread_arg_t;

void check_halt_file(int tid){
    printf("Thread %d: Waiting for haltcode file /tmp/haltcode to continue...\n", tid);
    fflush(stdout);
    while(access("/tmp/haltcode", F_OK) != 0) {
        //spin wait for haltcode file
    }
    printf("Thread %d: Haltcode file detected, continuing execution\n", tid);
    fflush(stdout);
    return;
}

void *thread_main(void *arg) {
    thread_arg_t *ta = (thread_arg_t*)arg;
    int tid   = ta->tid;
    int total = ta->nthreads;

    printf("[T%d] started\n", tid);
    fflush(stdout);

    
    splash_barrier(Global, total, tid);
    check_halt_file(tid);

    // Every thread participates in ALL rounds: 0 .. total-1
    // In round i, only thread i actually does the writes.
    for (int i = 0; i < total; i++) {
        int idx0, idx1;
        volatile unsigned char *q0, *q1;

        // Touch first DSM barrier page
        idx0 = current_barrier_index;
        q0   = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
        q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

        fprintf(stderr, " tid %d wrote to DSM barrier page %p (index=%d)\n",
                tid, (void*)q0, idx0);

        current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;


        fflush(stdout);
        if (i == tid) {
            
        // Now touch ALL pages of the test region
        printf("[T%d] My turn (round %d) → writing %d pages in region\n",
            tid, i, num_pages);
            for (int p = 0; p < num_pages; p++) {
                volatile char *page = (volatile char*)region + (size_t)p * PAGE_SIZE;
                page[0] ^= 1;  // trigger write fault on test region
            }
        }

        // Touch second DSM barrier page
        idx1 = current_barrier_index;
        q1   = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
        q1[0] = (unsigned char)(q1[0] ^ 1);

        fprintf(stderr, " tid %d wrote to DSM barrier page %p (index=%d)\n",
                tid, (void*)q1, idx1);

        current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

    

    }

    printf("[T%d] done\n", tid);
    fflush(stdout);
    return NULL;
}

// -----------------------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------------------
int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <num_threads> <num_pages>\n", argv[0]);
        return 1;
    }

    num_threads = atoi(argv[1]);
    num_pages   = atoi(argv[2]);

    printf(" DSM test: %d threads, %d pages\n",
           num_threads, num_pages);

    // ----------------------------------------------------
    // Init Global
    // ----------------------------------------------------
    Global = malloc(sizeof(GlobalMemory));
    memset(Global, 0, sizeof(GlobalMemory));
    pthread_mutex_init(&(Global->start).mutex, NULL);
    pthread_cond_init(&(Global->start).cv, NULL);

    // ----------------------------------------------------
    // Init DSM barrier pages (8 pages)
    // ----------------------------------------------------
    dsm_init_barrier_pages();

    // ----------------------------------------------------
    // Map region for testing and print /tmp/ranges.txt
    // ----------------------------------------------------
    size_t length = (size_t)num_pages * PAGE_SIZE;
    region = mmap(NULL, length,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                  -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap region");
        exit(1);
    }

    FILE *fr = fopen("/tmp/ranges.txt","w");
    if (fr) {
        fprintf(fr, "base=%p page_size=%d num_pages=%d\n",
                region, PAGE_SIZE, num_pages);
        fclose(fr);
    }

    for (int p = 0; p < num_pages; p++) {
        volatile char *page = (volatile char*)region + p * PAGE_SIZE;
        page[0] = 0;
    }

    printf("[MAIN] region mapped at %p (%zu bytes)\n",
           region, length);

    // ----------------------------------------------------
    // Launch worker threads: 0..num_threads-2
    // ----------------------------------------------------
    pthread_t tids[num_threads];
    thread_arg_t args[num_threads];

    int tid;
    for (tid = 0; tid < num_threads - 1; tid++) {
        args[tid].tid      = tid;
        args[tid].nthreads = num_threads;
        pthread_create(&tids[tid], NULL, thread_main, &args[tid]);
    }

    // Main thread is the last logical TID
    int my_tid = num_threads - 1;

    printf("[T%d] startedd\n", my_tid);
    fflush(stdout);

    static unsigned long *iteration_times = NULL;

    // Allocate iteration_times for ALL iterations
    iteration_times = malloc(sizeof(unsigned long) * num_threads);
    if (!iteration_times) {
        perror("malloc iteration_times");
        exit(1);
    }
    memset(iteration_times, 0, sizeof(unsigned long) * num_threads);

    
    splash_barrier(Global, num_threads, my_tid);
    check_halt_file(my_tid);
    // Every thread participates in ALL rounds: 0 .. num_threads-1
    // In round i, only thread i actually does the writes.
    for (int i = 0; i < num_threads; i++) {
        unsigned long t0 = now_us();
        int idx0, idx1;
        volatile unsigned char *q0, *q1;

        // Touch first DSM barrier page
        idx0 = current_barrier_index;
        q0   = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
        q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

        fprintf(stderr, " tid %d wrote to DSM barrier page %p (index=%d)\n",
                my_tid, (void*)q0, idx0);

        current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        if (i == my_tid) {
            
            // Now touch ALL pages of the test region
            printf("[T%d] My turn (round %d) → writing %d pages in region\n",
                my_tid, i, num_pages);
            for (int p = 0; p < num_pages; p++) {
                volatile char *page = (volatile char*)region + (size_t)p * PAGE_SIZE;
                page[0] ^= 1;  // trigger write fault on test region
            }
        }
        // Touch second DSM barrier page
        idx1 = current_barrier_index;
        q1   = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
        q1[0] = (unsigned char)(q1[0] ^ 1);

        fprintf(stderr, " tid %d wrote to DSM barrier page %p (index=%d)\n",
                my_tid, (void*)q1, idx1);

        current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

        fflush(stdout);
        unsigned long t1 = now_us();   // <--- END TIME (local)
        iteration_times[i] = t1 - t0;  // STORE
    }

    // ----------------------------------------------------
    // Write iteration times to file
    // ----------------------------------------------------
    FILE *ft = fopen("/tmp/iteration_times.txt", "w");
    if (!ft) {
        perror("fopen /tmp/iteration_times.txt");
    } else {
        fprintf(ft, "iteration,time_us\n");
        for (int i = 0; i < num_threads; i++) {
            fprintf(ft, "%d,%lu\n", i, iteration_times[i]);
        }
        fclose(ft);
        printf(" iteration times written to cat /tmp/iteration_times.txt \n");
    }
  
    printf(" ALL DONE.\n");
    return 0;
}
