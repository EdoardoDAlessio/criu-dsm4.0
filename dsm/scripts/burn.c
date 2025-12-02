#include <pthread.h>

void *burn(void *arg) {
    while (1) asm volatile("");
}

int main(int argc, char **argv) {
    int n = atoi(argv[1]);
    pthread_t th[n];
    for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, burn, NULL);
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
}

