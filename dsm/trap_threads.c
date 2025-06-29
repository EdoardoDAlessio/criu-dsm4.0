#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/stat.h>

typedef int (*pthread_create_t)(pthread_t *, const pthread_attr_t *,
                                void *(*)(void *), void *);

static pthread_create_t real_pthread_create = NULL;

struct thread_args_wrapper {
    void *(*start_routine)(void *);
    void *arg;
};



int is_criu_restore_mode() {
    struct stat st;
    // This file only exists during restore
    return stat("/tmp/.restore_flag", &st) == 0;
}


void *trampoline(void *arg) {
    fprintf(stderr, "[DEBUG] is_criu_restore_mode(): %d\n", is_criu_restore_mode() );
    if (!is_criu_restore_mode()) {
        pid_t tid = syscall(SYS_gettid);
        fprintf(stderr, "🔒 Trapping thread %d\n", tid);
        kill(tid, SIGSTOP);
    } 

    struct thread_args_wrapper *wrap = (struct thread_args_wrapper *)arg;
    void *ret = wrap->start_routine(wrap->arg);
    free(wrap);
    return ret;
}



int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    if (!real_pthread_create)
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");

    struct thread_args_wrapper *wrap = malloc(sizeof(*wrap));
    wrap->start_routine = start_routine;
    wrap->arg = arg;

    fprintf(stderr, "🎯 pthread_create trapped\n");
    return real_pthread_create(thread, attr, trampoline, wrap);
}

