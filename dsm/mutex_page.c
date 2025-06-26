#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>


int globall = 0;

__attribute__((aligned(4096))) char pad[4096];  // Force alignment and ensure 1 full page skip

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Function run by the thread
void *thread_func(void *arg) {
    int tid = *((int *)arg);

    while (1) {
        pthread_mutex_lock(&mutex);
        //globall++;
        printf("Doing nothing\n");
        //printf("Global variable at address: %p\n", (void *)&globall);
        //printf("Thread[%d] incremented globall to %d\n", tid, globall);
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    return NULL;
}

int main() {
    pthread_t thread;
    int thread_id = 1;
    printf("Global variable at address: %p\n", (void *)&globall);

    // Create the thread
    pthread_create(&thread, NULL, thread_func, &thread_id);

    // Main thread also modifies the globall variable
    while (1) {
        pthread_mutex_lock(&mutex);
        globall++; 

        printf("Global variable at address: %p\n", (void *)&globall);
        printf("Thread[0] incremented globall to %d\n", globall);
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    pthread_join(thread, NULL);
    return 0;
}
