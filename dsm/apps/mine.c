#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

int global = 0;  // Shared global variable
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread_func(void *arg) {
    int tid = *((int *)arg);
    free(arg);  // Free the dynamically allocated memory

    while (1) {
        pthread_mutex_lock(&mutex);
        global++;
        
        printf("Global variable at address: %p\n", (void *)&global);
        printf("Thread[%d] incremented global to %d\n", tid, global);
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <number_of_threads>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int num_threads = atoi(argv[1]) - 1;
    if (num_threads < 1) {
        fprintf(stderr, "Please specify a positive number of threads.\n");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[num_threads];

    printf("Global variable at address: %p\n", (void *)&global);

    for (int i = 0; i < num_threads; i++) {
        int *tid = malloc(sizeof(int));
        *tid = i + 1;
        if (pthread_create(&threads[i], NULL, thread_func, tid) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    // Main thread behaves as thread[0]
    while (1) {
        pthread_mutex_lock(&mutex);
        global++; 

        printf("Global variable at address: %p\n", (void *)&global);
        printf("Thread[0] incremented global to %d\n", global);
        pthread_mutex_unlock(&mutex);

        sleep(1); // Simulate some work
    }

    // Not reached, but included for completeness
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
