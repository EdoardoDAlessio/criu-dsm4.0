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


// Per-thread mode array: 0 = read-only, 1 = write
int *thread_mode = NULL;

int done = 0;
// -----------------------------------------------------------------------------
// GLOBAL MEMORY + DSM BARRIER
// -----------------------------------------------------------------------------
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cv;
    unsigned long   counter;
    unsigned long   cycle;
} start_barrier_t;

typedef struct GlobalMemory {
    start_barrier_t start;
} GlobalMemory;

GlobalMemory *Global;

static inline unsigned long now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000UL + tv.tv_usec;
}

void splash_barrier(GlobalMemory *G, int P, int tid) {
    pthread_mutex_lock(&(G->start).mutex);

    unsigned long Cycle = G->start.cycle;
    if (++G->start.counter != P) {
        long Cancel, Temp;
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &Cancel);
        while (Cycle == G->start.cycle)
            pthread_cond_wait(&(G->start).cv, &(G->start).mutex);
        pthread_setcancelstate(Cancel, &Temp);
    } else {
        G->start.cycle ^= 1;
        G->start.counter = 0;
        pthread_cond_broadcast(&(G->start).cv);
    }

    pthread_mutex_unlock(&(G->start).mutex);
}

// -----------------------------------------------------------------------------
// DSM barrier pages
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
        perror("mmap barrier_region");
        exit(1);
    }

    for (int i = 0; i < NUM_BARRIER_PAGES; i++)
        ((volatile char*)barrier_region)[i * page_size] = 0;

    // WRITE /tmp/dsm_barrier_pages.txt --------------- RESTORED
    FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "w");
    if (f) {
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n",
                barrier_region, page_size, NUM_BARRIER_PAGES);
        fclose(f);
    }

    fprintf(stderr, "[DSM] barrier region at %p (%d pages)\n",
            barrier_region, NUM_BARRIER_PAGES);
}

// -----------------------------------------------------------------------------
// LOCAL REGION & GLOBAL VARIABLES
// -----------------------------------------------------------------------------
static void *region = NULL;
int num_threads = 0;
int num_pages   = 0;
int num_repeats = 0;
int total_rounds = 0;

// per-thread timing matrix
unsigned long **times_us;

// -----------------------------------------------------------------------------
// THREAD ARGS
// -----------------------------------------------------------------------------
typedef struct {
    int tid;
    int nthreads;
} thread_arg_t;

void check_halt_file(int tid) {
    printf("Thread %d waiting for /tmp/haltcode...\n", tid);
    fflush(stdout);
    while (access("/tmp/haltcode", F_OK) != 0) {
        usleep(10000);
    }
    printf("Thread %d continues\n", tid);
    fflush(stdout);
}

// -----------------------------------------------------------------------------
// THREAD MAIN — DSM logic untouched, only wrapped with timing
// -----------------------------------------------------------------------------
void *thread_main(void *arg) {
    thread_arg_t *ta = (thread_arg_t*)arg;
    int tid   = ta->tid;
    int total = ta->nthreads;

    check_halt_file(tid);

    int round_id = 0;

    for (int rep = 0; rep < num_repeats; rep++) {
        for (int owner = 0; owner < total; owner++) {

            unsigned long t0 = now_us();   // time start

            // FIRST DSM barrier touch — DO NOT MODIFY
            int idx0 = current_barrier_index;
            volatile unsigned char *q0 =
                (volatile unsigned char*)barrier_region + idx0 * page_size;
            q0[0] ^= 1;

            //fprintf(stderr, " tid %d wrote to DSM barrier page %p (index=%d)\n",                    tid, (void*)q0, idx0);

            current_barrier_index =
                (current_barrier_index + 1) % NUM_BARRIER_PAGES;

            // OWNER performs ALL page writes — UNTOUCHED DSM BEHAVIOR
            if (tid == owner) {
                if( tid == 0 || tid == 2 ){//write page fault
                    printf("[T%d] rep %d owner-turn (%d) → writing %d pages\n",
                        tid, rep, owner, num_pages);

                    for (int p = 0; p < num_pages; p++) {
                        volatile char *page =
                            (volatile char*)region + p * PAGE_SIZE;
                        page[0] ^= 1;
                    }
                }else{ //thread 1 and 2 write 
                    printf("[T%d] rep %d owner-turn (%d) → reading %d pages\n",
                        tid, rep, owner, num_pages);

                    for (int p = 0; p < num_pages; p++) {
                        volatile char *page = (volatile char*)region + p * PAGE_SIZE;
                        volatile char tmp = page[0];
                    }
                }
               
            }

            // SECOND DSM barrier touch — DO NOT MODIFY
            int idx1 = current_barrier_index;
            volatile unsigned char *q1 =   (volatile unsigned char*)barrier_region + idx1 * page_size;
            q1[0] ^= 1;

            //fprintf(stderr," tid %d wrote to DSM barrier page %p (index=%d)\n",     tid, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

            unsigned long t1 = now_us();   // time end

            times_us[tid][round_id] = t1 - t0;   // STORE TIMING

            round_id++;
        }
    }

    pthread_mutex_lock(&Global->start.mutex);

    FILE *ft = fopen("/tmp/page_test_times.csv", "w");
    fprintf(ft, "thread,round,time_us,avg0,avg1,avg2\n");

    // For each thread compute averages of groups r%3 == 0,1,2
    for (int t = 0; t < num_threads; t++) {

        unsigned long sums[3] = {0,0,0};
        int counts[3] = {0,0,0};

        for (int r = 0; r < total_rounds; r++) {
            unsigned long v = times_us[t][r];

            // write raw values
            fprintf(ft, "%d,%d,%lu", t, r, v);

            // accumulate into groups (0,1,2)
            int bucket = r % 3;
            sums[bucket] += v;
            counts[bucket] += 1;

            // write placeholder for averages
            fprintf(ft, ",,,\n");
        }

        // compute averages
        double avg0 = (counts[0] ? (double)sums[0] / counts[0] : 0.0);
        double avg1 = (counts[1] ? (double)sums[1] / counts[1] : 0.0);
        double avg2 = (counts[2] ? (double)sums[2] / counts[2] : 0.0);

        // append summary line for this thread
        fprintf(ft,
            "thread %d averages,, ,%.2f,%.2f,%.2f\n",
            t, avg0, avg1, avg2);
    }

    fflush(ft);
    fclose(ft);

    printf("Saved timings to /tmp/page_test_times.csv\n");
    pthread_mutex_unlock(&Global->start.mutex);


    printf("[T%d] done\n", tid);
    return NULL;
}

// -----------------------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------------------
int main(int argc, char **argv) {

    if (argc != 4) {
        printf("Usage: %s <num_threads> <num_pages> <num_repeats>\n",
               argv[0]);
        return 1;
    }

    num_threads = atoi(argv[1]);
    num_pages   = atoi(argv[2]);
    num_repeats = atoi(argv[3]);
    total_rounds = num_threads * num_repeats;

    // Init global barrier memory
    Global = malloc(sizeof(GlobalMemory));
    memset(Global, 0, sizeof(GlobalMemory));
    pthread_mutex_init(&(Global->start).mutex, NULL);
    pthread_cond_init(&(Global->start).cv, NULL);

    // DSM barrier initialization
    dsm_init_barrier_pages();

    // Allocate local test region
    size_t length = (size_t)num_pages * PAGE_SIZE;
    region = mmap(NULL, length,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                  -1, 0);
    if (region == MAP_FAILED) {
        perror("region mmap");
        exit(1);
    }

    // WRITE /tmp/ranges.txt ---- RESTORED
    FILE *fr = fopen("/tmp/ranges.txt","w");
    if (fr) {
        fprintf(fr,
                "base=%p page_size=%d num_pages=%d\n",
                region, PAGE_SIZE, num_pages);
        fclose(fr);
    }

    memset(region, 0, length);

    // Allocate timing matrix
    times_us = malloc(sizeof(unsigned long*) * num_threads);
    for (int t = 0; t < num_threads; t++) {
        times_us[t] = malloc(sizeof(unsigned long) * total_rounds);
        memset(times_us[t], 0, sizeof(unsigned long) * total_rounds);
    }

    // Launch threads
    pthread_t thr[num_threads];
    thread_arg_t args[num_threads];
    //int order[3] = {0,2,1}; //th0 modifies then main reads, th1 reads 
    int order[3] = {0,1,2}; //th0 modifies then th1 reads lasly main reads

    for (int t = 0; t < num_threads - 1; t++) {
        args[t].tid = order[t];
        args[t].nthreads = num_threads;
        pthread_create(&thr[t], NULL, thread_main, &args[t]);
    }
    int t = num_threads - 1;
    args[t].tid = order[t];
    args[t].nthreads = num_threads;
    thread_main(&args[t]);


    sleep(5);
    printf("ALL DONE.\n");
    return 0;
}
