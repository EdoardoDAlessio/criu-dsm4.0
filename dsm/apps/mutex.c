#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

int global = 0;  // Shared global variable
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Function run by the thread
void *thread_func(void *arg) {
    int tid = *((int *)arg), i;

    while (1) {
        i = 0;
        pthread_mutex_lock(&mutex);
        //global++; 

        //printf("Global variable at address: %p\n", (void *)&global);
        //printf("Thread[0] incremented global to %d\n", global);
        while( i < 11 ){
            sleep(1);
            printf("Simulating work inside mutex THREAD, i from 0 to 10, i:%d\n", i);
            i++;
        }
        
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    return NULL;
}

int main() {
    pthread_t thread;
    int thread_id = 1, i;
    printf("Global variable at address: %p\n", (void *)&global);

    // Create the thread
    pthread_create(&thread, NULL, thread_func, &thread_id);

    // Main thread also modifies the global variable
    while (1) {
        i = 0;
        pthread_mutex_lock(&mutex);
        //global++; 

        //printf("Global variable at address: %p\n", (void *)&global);
        //printf("Thread[0] incremented global to %d\n", global);
        while( i < 11 ){
            sleep(1);
            printf("Simulating work inside mutex MAIN, i from 0 to 10, i:%d\n", i);
            i++;
        }
        
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    pthread_join(thread, NULL);
    return 0;
}
