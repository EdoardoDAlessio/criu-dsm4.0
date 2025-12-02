#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define MAX_THREADS 64

int local_threads = 0;
int restored = 1;   

// Global arrays
int thread_slot[MAX_THREADS];  // each thread's index
int thread_tid[MAX_THREADS];   // real Linux TID (0 or -1 = remote thread)

// Return real Linux TID
static inline int gettid_real() {
    return syscall(SYS_gettid);
}

void check_halt_file(int slot) {
    printf("Thread %d waiting for /tmp/haltcode ...\n", slot);
    while (access("/tmp/haltcode", F_OK) != 0) { }
    printf("Thread %d continuing\n", slot);
}

// ==========================================================
// Worker thread: local execution
// ==========================================================
void *worker(void *arg)
{
    int slot = *(int*)arg;
    thread_tid[slot] = gettid_real();
    check_halt_file(slot);

    restored++;
    // Store real Linux thread ID for this slot
    printf("[DSM] Local thread pos %d running with TID %d\n", slot, thread_tid[slot]);

   

    sleep(1 + (slot % 3));   // simulate some work

    printf("[DSM] Local thread pos %d finishing\n", slot);
    return NULL;
}

// ==========================================================
// MAIN DSM JOIN LOGIC
// ==========================================================
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        exit(1);
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Invalid number of threads\n");
        exit(1);
    }

    // --- Initialize ---
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_slot[i] = i;   // give slot index
        thread_tid[i]  = -1;  // -1 = not started / remote
    }

    pthread_t threads[num_threads];

    // --- Launch local threads ---
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, worker, &thread_slot[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    check_halt_file(-1);
    FILE *f = fopen("/tmp/restored_threads.txt", "r");
    if (f) {
        if (fscanf(f, "%d", &local_threads) == 1) {
            printf("[APP] Read barrier count from /tmp/restored_threads.txt: %d\n", local_threads);
        } else {
            printf("[APP] Failed to parse integer from /tmp/restored_threads.txt, using default count: %d\n", local_threads);
        }
        fclose(f);
    } else {
        printf("[APP] Could not open /tmp/restored_threads.txt, doing nothing\n");
        fflush(stdout);
        return;
    }

    while( restored < local_threads ){
        sleep(1);
    }

    // ======================================================
    // JOIN PHASE
    // ======================================================
    printf("\n[DSM] === JOIN PHASE ===\n");

    for (int i = 0; i < num_threads; i++) {

        if ( i < local_threads - 1 ) {
            // ---------------------------------------------------
            // LOCAL THREAD: join normally
            // ---------------------------------------------------
            printf("[DSM] Joining LOCAL thread slot %d (TID=%d)\n",
                    i, thread_tid[i]);

            pthread_join(threads[i], NULL);

            printf("[DSM] Local thread slot %d joined.\n", i);
        }
        else {
            // ---------------------------------------------------
            // REMOTE THREAD: wait for death file
            // ---------------------------------------------------
            // Remote TID must be written by the remote side into
            // thread_tid[i] BEFORE join phase.
            int tid = thread_tid[i];  // remote TID

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
    return 0;
}
