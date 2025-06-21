#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

// Struct to hold shared data
typedef struct {
    int *global;
    pthread_mutex_t *mutex;
    int tid;
} thread_args_t;

// Function run by the thread
void *thread_func(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;

    while (1) {
        pthread_mutex_lock(args->mutex);
        (*args->global)++;
        printf("Global variable at address: %p\n", (void *)args->global);
        printf("Thread[%d] incremented global to %d\n", args->tid, *args->global);
        pthread_mutex_unlock(args->mutex);

        sleep(1); // Simulate some work
    }

    return NULL;
}

int main() {
    int global = 0; // Shared variable moved into main
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_t thread;
    thread_args_t args;

    args.global = &global;
    args.mutex = &mutex;
    args.tid = 1;

    printf("Global variable at address: %p\n", (void *)&global);

    // Create the thread
    pthread_create(&thread, NULL, thread_func, &args);

    // Main thread also modifies the global variable
    while (1) {
        pthread_mutex_lock(&mutex);
        global++;
        printf("Global variable at address: %p\n", (void *)&global);
        printf("Thread[0] incremented global to %d\n", global);
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    pthread_join(thread, NULL);
    return 0;
}
