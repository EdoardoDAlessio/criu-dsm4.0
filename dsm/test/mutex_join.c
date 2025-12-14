#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <sys/syscall.h>

#define PAGE_SIZE 4096
#define ITER 100000
#define MAX_THREADS 64

/* ===================== Shared counter (mutex benchmark) ===================== */

static int *shared_counter;    // counter at offset 0 of the page
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/*************************************** DSM SHARED STATE **************************************/
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
    unsigned long mutex_time;
} GlobalMemory;

GlobalMemory *Global;   // the global pointer (unused here, but kept for consistency)

int local_threads  = 0;   // how many threads are actually local on this node
int auth_thread    = 0;   // unused here
int total_threads  = 0;   // total logical threads in the system (here = num_threads)
int dsm_active     = 0;
int server         = 0;
int done           = 0;

pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER; 

/* ===================== Mutex pages for DSM global lock ===================== */

#define NUM_BARRIER_PAGES 8

int count[NUM_BARRIER_PAGES];
static void *mutex_lock_page   = NULL;
static void *mutex_unlock_page = NULL;
static size_t page_size        = 0;
static int current_lock_page   = 0;  // global page index, rotated by every thread
static int current_unlock_page = 0;  // global page index, rotated by every thread

/* ===================== JOIN-related globals (from join.c) ================== */

int restored = 1;                      // how many local threads have started
int thread_slot[MAX_THREADS];          // logical position/slot
int thread_tid[MAX_THREADS];           // real Linux TID (0 or -1 = remote thread)

/* Return real Linux TID */
static inline int gettid_real() {
    return syscall(SYS_gettid);
}

/* ===================== DSM Mutex pages init ================================ */

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
        fprintf(stderr, "[APP] mmap failed (lock_page): %s\n", strerror(errno));
        mutex_lock_page = NULL;
        return;
    }

    mutex_unlock_page = mmap(NULL, length,
                             PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
                             -1, 0);
    if (mutex_unlock_page == MAP_FAILED) {
        fprintf(stderr, "[APP] mmap failed (unlock_page): %s\n", strerror(errno));
        mutex_unlock_page = NULL;
        return;
    }

    // Touch each page so they are faulted in
    for (int i = 0; i < NUM_BARRIER_PAGES; i++) {
        volatile char *p = (volatile char *)mutex_lock_page   + (size_t)i * page_size;
        volatile char *t = (volatile char *)mutex_unlock_page + (size_t)i * page_size;
        *p = 0;
        *t = 0;
    }

    FILE *f = fopen("/tmp/dsm_mutex.txt", "w");
    if (f) {
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n",
                mutex_lock_page, page_size, NUM_BARRIER_PAGES);
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n",
                mutex_unlock_page, page_size, NUM_BARRIER_PAGES);
        fclose(f);
    }

    fprintf(stderr,
            "[APP] lock region mapped at %p, %d pages (total %zu bytes), "
            "unlock: mmap at %p, %d pages (total %zu bytes) [/tmp/dsm_mutex.txt]\n",
            mutex_lock_page, NUM_BARRIER_PAGES, length,
            mutex_unlock_page, NUM_BARRIER_PAGES, length);
}

/* ===================== Halt file wait (reused) ============================= */

void check_halt_file(int id){
    printf("Thread/slot %d: Waiting for haltcode file /tmp/haltcode to continue...\n", id);
    fflush(stdout);
    while (access("/tmp/haltcode", F_OK) != 0) {
        // spin wait for haltcode file
        usleep(10000);
    }
    printf("Thread/slot %d: Haltcode file detected, continuing execution\n", id);
    fflush(stdout);
}

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

/* ===================== Worker: DSM mutex + join instrumentation ============ */

void *worker(void *arg) {
    struct timespec ts;
    ts.tv_sec = 0;        // seconds
    ts.tv_nsec = 5000000; // 5 ms = 5,000,000 ns

    int slot = *(int *)arg;   // logical thread slot
    int tid  = gettid_real(); // real Linux TID
    int idx0, idx1;
    volatile unsigned char *q0, *q1;

    if (slot < 0 || slot >= MAX_THREADS) {
        fprintf(stderr, "Invalid slot %d\n", slot);
        return NULL;
    }

    thread_tid[slot] = tid;

    // Wait for haltcode before starting actual work
    check_halt_file(slot);

    pthread_mutex_lock(&once_lock);
    if (!done) {
        Global->starttime = now_us();
        done = 1;
        
        FILE *f = fopen("/tmp/restored_threads.txt", "r");
        if (f) {
            if (fscanf(f, "%d", &local_threads) == 1)
                printf("[APP] Read barrier count from /tmp/restored_threads.txt: %d\n", local_threads);
            else
                printf("[APP] Failed to parse integer from /tmp/restored_threads.txt, using default count\n");
            fclose(f);
        }

        f = fopen("/tmp/authorized_barrier_thread.txt", "r");
        if (f) {
            if (fscanf(f, "%d", &auth_thread) == 1)
                printf("auth_thread:%d\n", auth_thread);
            fclose(f);
        } else {
            printf("[APP] Could not open /tmp/authorized_barrier_thread.txt, doing nothing\n");
            fflush(stdout);
        }
    }
    pthread_mutex_unlock(&once_lock);
    
    while(1){

        // Local mutex acquisition
        pthread_mutex_lock(&lock);

        // Global mutex acquisition: write to current barrier page
        idx0 = current_lock_page;
        q0 = (volatile unsigned char *)mutex_lock_page + (size_t)idx0 * page_size;
        q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

        fprintf(stderr, "[APP] slot %d wants mutex %p (index=%d)\n",
                slot, (void *)q0, idx0);

        // Advance index
        current_lock_page = (current_lock_page + 1) % NUM_BARRIER_PAGES;

        if(*shared_counter == ITER){
            
            // Global mutex release: write to next barrier page
            idx1 = current_unlock_page;
            q1 = (volatile unsigned char *)mutex_unlock_page + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] slot %d released mutex %p (index=%d)\n",
                    slot, (void *)q1, idx1);

            current_unlock_page = (current_unlock_page + 1) % NUM_BARRIER_PAGES;

            // Local mutex release
            pthread_mutex_unlock(&lock);

            break;
        } 

        // WORK: increment shared counter
        (*shared_counter)++;
        printf("Slot %d incremented counter to %d\n", slot, *shared_counter);

        // Global mutex release: write to next barrier page
        idx1 = current_unlock_page;
        q1 = (volatile unsigned char *)mutex_unlock_page + (size_t)idx1 * page_size;
        q1[0] = (unsigned char)(q1[0] ^ 1);

        fprintf(stderr, "[APP] slot %d released mutex %p (index=%d)\n",
                slot, (void *)q1, idx1);

        current_unlock_page = (current_unlock_page + 1) % NUM_BARRIER_PAGES;

        // Local mutex release
        pthread_mutex_unlock(&lock);

        if (nanosleep(&ts, NULL) != 0) {
            perror("nanosleep");
        }


    }
   
    printf("Thread %d exiting\n", slot);
    return NULL;
}

/* ===================== MAIN: mutex benchmark + DSM join ==================== */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "num_threads must be in 1..%d\n", MAX_THREADS);
        return 1;
    }

    total_threads = num_threads;

    // Initialize DSM mutex pages (global mutex mechanism)
    dsm_init_barrier_pages();
    if (!mutex_lock_page || !mutex_unlock_page) {
        fprintf(stderr, "Failed to initialize barrier pages\n");
        return 1;
    }

    Global = malloc(sizeof(GlobalMemory));
    memset(Global, 0, sizeof(GlobalMemory));
    pthread_mutex_init(&(Global->start).mutex, NULL);
    pthread_cond_init(&(Global->start).cv, NULL);


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

    // Init join-related arrays
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_slot[i] = i;
        thread_tid[i]  = -1;  // -1 = not started / remote
    }

    pthread_t threads[num_threads];

    // --- Launch local threads ---
    for (int i = 0; i < num_threads; i++) {
        if (i && pthread_create(&threads[i], NULL, worker, &thread_slot[i]) != 0) {
            perror("pthread_create");
            munmap(page, PAGE_SIZE);
            return 1;
        }
    }
    worker(&thread_slot[0]);


    Global->mutex_time = now_us();
    printf("[APP] Total mutex: %.3f s\n", (Global->mutex_time - Global->starttime)/1e6);
    
    // ===================== JOIN PHASE (DSM-style) =======================
    printf("\n[DSM] === JOIN PHASE ===\n");

    for (int i = 1; i < num_threads; i++) {

        if (i < local_threads ) {
            // LOCAL THREAD: join normally
            printf("[DSM] Joining LOCAL thread slot %d (TID=%d)\n",
                   i, thread_tid[i]);

            pthread_join(threads[i], NULL);

            printf("[DSM] Local thread slot %d joined.\n", i);
        } else {
            // REMOTE THREAD: wait for death file
            // Remote TID must be written by the remote side into thread_tid[i]
            int tid = thread_tid[i];  // remote TID or possibly a local thread
            if (tid <= 0) {
                // If nothing was set, just skip
                printf("[DSM] Slot %d has no remote TID, skipping remote join.\n", i);
                continue;
            }

            char filename[128];
            snprintf(filename, sizeof(filename),
                     "/tmp/thread_%d_dead", tid);

            printf("[DSM] Waiting for REMOTE thread slot %d (TID=%d) at %s\n",
                   i, tid, filename);

            while (access(filename, F_OK) != 0) {
                usleep(10000);
            }

            printf("[DSM] Remote thread slot %d (TID=%d) terminated.\n",
                   i, tid);
        }
    }

    printf("\n[DSM] All threads joined. DSM execution complete.\n");
    Global->finishtime = now_us();    
    printf("[APP] Total mutex: %.6f, join time:%.6f\n",  (Global->mutex_time - Global->starttime)/1e6,  (Global->finishtime - Global->mutex_time)/1e6);
    // --- Print result ---
    printf("Final counter = %d\n",
           *shared_counter, local_threads * ITER);
    
        
    munmap(page, PAGE_SIZE);
    return 0;
}
