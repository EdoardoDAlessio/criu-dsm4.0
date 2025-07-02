#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

int global = 0;  // Shared global variable
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Function run by each worker thread
void *thread_func(void *arg) {
    int tid = *((int *)arg);
    int i;

    while (1) {
        i = 0;
        pthread_mutex_lock(&mutex);

        while (i < 11) {
            sleep(1);
            printf("Simulating work inside mutex THREAD[%d], i from 0 to 10, i:%d\n", tid, i);
            i++;
        }

        pthread_mutex_unlock(&mutex);
        sleep(1);  // Simulate non-critical work
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        return 1;
    }

    int num_threads = atoi(argv[1]);
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    int *thread_ids = malloc(num_threads * sizeof(int));

    printf("Global variable at address: %p\n", (void *)&global);

    for (int i = 0; i < num_threads; ++i) {
        thread_ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, thread_func, &thread_ids[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // Main thread does nothing — idle
    while (1) {
        pause();  // Sleep until a signal arrives
    }

    // Unreachable, but good practice
    for (int i = 0; i < num_threads; ++i)
        pthread_join(threads[i], NULL);

    free(threads);
    free(thread_ids);
    return 0;
}
