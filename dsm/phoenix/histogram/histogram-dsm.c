/* Copyright (c) 2007-2009, Stanford University
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of Stanford University nor the names of its 
*       contributors may be used to endorse or promote products derived from 
*       this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY STANFORD UNIVERSITY ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL STANFORD UNIVERSITY BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/ 
#include <stdint.h>

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>

#include "stddefines.h"

#define IMG_DATA_OFFSET_POS 10
#define BITS_PER_PIXEL_POS 28


/*************************************** DSM ********************************************************/
#define DSM 1

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define _GNU_SOURCE     // or _BSD_SOURCE on really old systems
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

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
    unsigned long initdonetime;
} GlobalMemory;

GlobalMemory *Global;   // the global pointer

int local_threads = 0;
int auth_thread = 0;   
int total_threads = 0;
int dsm_active = 0;
int server = 0;
int done;
int iterations = 1;
pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER; 



#define NUM_BARRIER_PAGES 8

int count[NUM_BARRIER_PAGES];
static void *barrier_region = NULL;
static size_t page_size = 0;
pthread_once_t barrier_once = PTHREAD_ONCE_INIT;
static int current_barrier_index = 0;  // global page index, rotated by auth_thread


/* call this once at program start */
void dsm_init_barrier_pages(void) {
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;

    size_t length = NUM_BARRIER_PAGES * page_size;

    barrier_region = mmap(NULL, length,
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
                          -1, 0);
    if (barrier_region == MAP_FAILED) {
        fprintf(stderr, "[APP] mmap failed: %s\n", strerror(errno));
        return;
    }

    // Touch each page so they are faulted in
    for (int i = 0; i < NUM_BARRIER_PAGES; i++) {
        volatile char *p = (volatile char *)barrier_region + i * page_size;
        *p = 0;
    }

    FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "w");
    if (f) {
        fprintf(f, "base=%p page_size=%zu num_pages=%d\n",
                barrier_region, page_size, NUM_BARRIER_PAGES);
        fclose(f);
    }

    fprintf(stderr, "[APP] barrier region mapped at %p, %d pages (total %zu bytes) [/tmp/dsm_barrier_pages.txt]\n",
            barrier_region, NUM_BARRIER_PAGES, length);
}


void check_halt_file(int tid){
    printf("Thread %d: Waiting for haltcode file /tmp/haltcode to continue...\n", tid);
    fflush(stdout);
    while(access("/tmp/haltcode", F_OK) != 0) {
        //spin wait for haltcode file
    }
    printf("Thread %d: Haltcode file detected, continuing execution\n", tid);
    fflush(stdout);
    return;
}

void splash_barrier(GlobalMemory *Global, int P, int tid) {
    unsigned long Error, Cycle;
    long Cancel, Temp;

    Error = pthread_mutex_lock(&(Global->start).mutex);
    if (Error != 0) {
        fprintf(stderr, "Error while trying to get lock in barrier.\n");
        exit(-1);
    }

    Cycle = (Global->start).cycle;
    if (++(Global->start).counter != P) {
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &Cancel);
        while (Cycle == (Global->start).cycle) {
            Error = pthread_cond_wait(&(Global->start).cv, &(Global->start).mutex);
            if (Error != 0) {
                break;
            }
        }
        pthread_setcancelstate(Cancel, &Temp);
    } else {
        (Global->start).cycle = !(Global->start).cycle;
        (Global->start).counter = 0;
        Error = pthread_cond_broadcast(&(Global->start).cv);
    }

    pthread_mutex_unlock(&(Global->start).mutex);
}


/*************************************** DSM ********************************************************/

int swap;      // to indicate if we need to swap byte order of header information

typedef struct {
    int tid;
    unsigned char *data;
    uint64_t data_pos;   // offset into fdata
    uint64_t data_len;   // length in bytes
    uint64_t red[256];
    uint64_t green[256];
    uint64_t blue[256];
} thread_arg_t;

/* test_endianess
 *
 */
void test_endianess() {
   unsigned int num = 0x12345678;
   char *low = (char *)(&(num));
   if (*low ==  0x78) {
      printf("No need to swap\n");
      swap = 0;
   }
   else if (*low == 0x12) {
      printf("Need to swap\n");
      swap = 1;
   }
   else {
      printf("Error: Invalid value found in memory\n");
      exit(1);
   } 
}

/* swap_bytes
 *
 */
void swap_bytes(char *bytes, int num_bytes) {
   int i;
   char tmp;
   
   for (i = 0; i < num_bytes/2; i++) {
      printf("Swapping %d and %d\n", bytes[i], bytes[num_bytes - i - 1]);
      tmp = bytes[i];
      bytes[i] = bytes[num_bytes - i - 1];
      bytes[num_bytes - i - 1] = tmp;   
   }
}

/* calc_hist
 * Function that computes the histogram for the region
 * assigned to each thread
 */
void *calc_hist(void *arg) {
   
    uint64_t  *red;
    uint64_t  *green;
    uint64_t  *blue;
    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    unsigned char *val;
    int tid = thread_arg->tid;
    int idx0, idx1;
    volatile unsigned char *q0, *q1;

    if (dsm_active) {
        check_halt_file(tid);

        pthread_mutex_lock(&once_lock);
        if (!done) {
            Global->starttime = now_us();
            done = 1;   
            {
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
                    return NULL;
                }
                f = fopen("/tmp/authorized_barrier_thread.txt", "r");
                if (f) {
                    if (fscanf(f, "%d", &auth_thread) == 1) {
                        printf("auth_thread:%d\n", auth_thread);
                    } else {
                        printf("[APP] Failed to parse integer from /tmp/authorized_barrier_thread.txt, using default count: %d\n", local_threads);
                    }
                    fclose(f);
                } else {
                    printf("[APP] Could not open /tmp/authorized_barrier_thread.txt, doing nothing\n");
                    fflush(stdout);
                    return NULL;
                }
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&once_lock);
    }

    red   = thread_arg->red;
    green = thread_arg->green;
    blue  = thread_arg->blue;
   
    /* Print histogram array addresses */
    printf("[T%d] Address of blue=%p, green=%p, red=%p\n",
        thread_arg->tid, (void*)blue, (void*)green, (void*)red);
    printf("[T%d] My page base=%p, page_aligned=%p, data_start=%" PRIu64 ", len=%" PRIu64 " bytes\n",
        thread_arg->tid,
        (void *)thread_arg,
        (void *)((intptr_t)thread_arg & ~(PAGE_SIZE - 1)),
        thread_arg->data_pos,
        thread_arg->data_len);

    for (int j = 0; j < iterations; j++ ) {
        uint64_t end = thread_arg->data_pos + thread_arg->data_len;
        for (uint64_t i = thread_arg->data_pos; 
             i < end; 
             i += 3) {
                
            val = &(thread_arg->data[i]);
            blue[*val]++;
        
            val = &(thread_arg->data[i+1]);
            green[*val]++;
        
            val = &(thread_arg->data[i+2]);
            red[*val]++;   
        }
    }

    if (dsm_active && tid) {
        splash_barrier(Global, local_threads, tid); //sync LOCAL threads
        if (dsm_active && tid) {
            splash_barrier(Global, local_threads, tid); //sync LOCAL threads
            if (barrier_region && tid == auth_thread ) {
                // Touch first page for this barrier
                idx0 = current_barrier_index;
                q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
                q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

                fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
                        auth_thread, (void*)q0, idx0);

                // Advance index
                current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

                // Touch second, different page this barrier.
                idx1 = current_barrier_index;
                q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
                q1[0] = (unsigned char)(q1[0] ^ 1);

                fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
                       auth_thread, (void*)q1, idx1);

                current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
            }
            splash_barrier(Global, local_threads, tid);
        }
        splash_barrier(Global, local_threads, tid);
    }

    return (void *)0;
}


int main(int argc, char *argv[]) {
      
    int i, j;
    int fd;
    char *fdata;
    struct stat finfo;
    char * fname;
    pthread_t *pid;
    pthread_attr_t attr;
    thread_arg_t **arg;
    uint64_t red[256];
    uint64_t green[256];
    uint64_t blue[256]; 
    int num_procs;
    uint64_t num_per_thread;
    uint64_t excess;
    uint64_t npixels = 0;
    
    int idx0, idx1;
    volatile unsigned char *q0, *q1;

    if (argc < 2) {
        printf("USAGE: %s <bitmap filename> [iterations_if_DSM]\n", argv[0]);
        exit(1);
    }
   
    fname = argv[1];
    
    // Read in the file
    if ((fd = open(fname, O_RDONLY)) < 0) {
        perror("open");
        exit(1);
    }
    // Get the file info (for file length)
    if (fstat(fd, &finfo) < 0) {
        perror("fstat");
        exit(1);
    }
    // Memory map the file
    if ((fdata = mmap(0, finfo.st_size, 
        PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == NULL) {
        perror("mmap");
        exit(1);
    }
    
    if ((fdata[0] != 'B') || (fdata[1] != 'M')) {
        printf("File is not a valid bitmap file. Exiting\n");
        exit(1);
    }
   
    test_endianess();    // will set the variable "swap"
    
    unsigned short *bitsperpixel = (unsigned short *)(&(fdata[BITS_PER_PIXEL_POS]));
    if (swap) {
        swap_bytes((char *)(bitsperpixel), sizeof(*bitsperpixel));
    }
    if (*bitsperpixel != 24) {    // ensure its 3 bytes per pixel
        printf("Error: Invalid bitmap format - ");
        printf("This application only accepts 24-bit pictures. Exiting\n");
        exit(1);
    }
    
    // DATA OFFSET IS 4 BYTES, NOT 2
    uint32_t *data_pos_ptr = (uint32_t *)(&(fdata[IMG_DATA_OFFSET_POS]));
    uint32_t data_pos = *data_pos_ptr;
    if (swap) {
        swap_bytes((char *)(&data_pos), sizeof(data_pos));
    }
    
    uint64_t filesize      = (uint64_t)finfo.st_size;
    uint64_t imgdata_bytes = filesize - (uint64_t)data_pos;
    uint64_t num_pixels    = imgdata_bytes / 3;  // 3 bytes per pixel

    printf("This file has %" PRIu64 " bytes of image data, %" PRIu64 " pixels\n",
           imgdata_bytes, num_pixels);

    printf("Starting pthreads histogram\n");
    

    memset(&(red[0]),   0, sizeof(uint64_t) * 256);
    memset(&(green[0]), 0, sizeof(uint64_t) * 256);
    memset(&(blue[0]),  0, sizeof(uint64_t) * 256);
    
    /* Set a global scope */
    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
   
    // DSM init page for mypthread_barrier 
    Global = (struct GlobalMemory *) malloc(sizeof(struct GlobalMemory));
    const char *env = getenv("DSM");
    if (env) {
        printf("DSM detected, using DSM pthread_barrier\n");
        dsm_init_barrier_pages();
        dsm_active = 1;
        num_procs = atoi(env);  // threads count from DSM env
        if (argc < 3) {
            fprintf(stderr, "When DSM is active, pass iterations as second arg\n");
            exit(1);
        }
        iterations = atoi(argv[2]);
        npixels = num_pixels * (uint64_t)iterations;

        printf("Num threads:%d, pixels:%" PRIu64 ", iterations:%d, size of thread arg:%zu\n",
               num_procs, npixels, iterations, sizeof(thread_arg_t));
    } else {
        CHECK_ERROR((num_procs = sysconf(_SC_NPROCESSORS_ONLN)) <= 0);
        iterations = 1;
        npixels = num_pixels;
    }

    // compute work division
    num_per_thread = num_pixels / (uint64_t)num_procs;
    excess         = num_pixels % (uint64_t)num_procs;
    
    CHECK_ERROR((pid = (pthread_t *)malloc(sizeof(pthread_t) * num_procs)) == NULL);
    CHECK_ERROR((arg = (thread_arg_t **)malloc(sizeof(thread_arg_t *) * num_procs)) == NULL);


    /* Assign portions of the image to each thread */
    uint64_t curr_pos = (uint64_t)data_pos;
    FILE *f = fopen("/tmp/ranges.txt", "w");
    for (i = 0; i < num_procs; i++) {
        // one region per thread for DSM visibility
        arg[i] = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (arg[i] == MAP_FAILED) {
            perror("mmap thread_arg_t");
            exit(1);
        }

        // Force physical allocation: touch each page
        volatile char *p = (volatile char *)arg[i];
        p[0] = 0;

        if (f) {
            fprintf(f, "base=%p page_size=%zu num_pages=%d\n", arg[i], page_size, 2);
            fflush(f);
            printf("Thread %d, base=%p page_size=%zu num_pages=%d\n", i, arg[i], page_size, 2);
        }

        memset(arg[i], 0, sizeof(thread_arg_t));
        arg[i]->tid  = i;
        arg[i]->data = (unsigned char *)fdata;
        arg[i]->data_pos = curr_pos;
        arg[i]->data_len = num_per_thread;
        if (excess > 0) {
            arg[i]->data_len++;
            excess--;
        }

        arg[i]->data_len *= 3;   // 3 bytes per pixel
        curr_pos += arg[i]->data_len;
        if (i) {
            pthread_create(&(pid[i]), &attr, calc_hist, (void *)(arg[i]));
        }
    }
    if (f) fclose(f);

    // run on main thread too
    calc_hist(arg[0]);
    

    if (dsm_active) {
        splash_barrier(Global, local_threads, 0); //sync LOCAL threads
        if (barrier_region ) {
            // Touch first page for this barrier
            idx0 = current_barrier_index;
            q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
            q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

            fprintf(stderr, "[APP] main %d wrote to barrier page %p (index=%d)\n",
                   auth_thread, (void*)q0, idx0);

            // Advance index
            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

            for (i = 0; i < num_procs; i++) {
                volatile char *pp = (volatile char *)arg[i];
                char h = (unsigned char)(pp[0] ^ 1);     
                h = (unsigned char)(pp[PAGE_SIZE+1] ^ 1);    
                (void)h;
            }
            printf("==========================\n\n");
            
            // Touch second, different page this barrier.
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] main %d wrote to barrier page %p (index=%d)\n",
                   auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }
        splash_barrier(Global, local_threads, 0);
    } else {         
        for (i = 0; i < num_procs; i++) {
            pthread_join(pid[i] , NULL);   
        }
    }
    
    for (i = 0; i < num_procs; i++) {
        for (j = 0; j < 256; j++) {
            red[j]   += arg[i]->red[j];
            green[j] += arg[i]->green[j];
            blue[j]  += arg[i]->blue[j];
        }
    }

    Global->finishtime = now_us();

    
    char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/histogram";
    char outname[512];
    snprintf(outname, sizeof(outname),
         "%s/histogram_%" PRIu64 "_check.txt", 
            dir,
         npixels);

    /* Verify histogram file contents against in-memory arrays */
    FILE *inf = fopen(outname, "r");
    if (!inf) {
        printf("Error opening histogram check file %s for verification\n", outname);
        perror("fopen verify");
        exit(1);
    }

    char header[128];
    fgets(header, sizeof(header), inf);  

    int pos;
    uint64_t b, g, r;

    int mismatches = 0;
    for (i = 0; i < 256; i++) {
        if (fscanf(inf, "%d %" SCNu64 " %" SCNu64 " %" SCNu64, &pos, &b, &g, &r) != 4) {
            fprintf(stderr, "[ERR] Failed to read line %d\n", i);
            break;
        }
        if (pos != i ||
            b != blue[i] ||
            g != green[i] ||
            r != red[i]) {
            fprintf(stderr,
                "[Mismatch] pos=%d file=(%" PRIu64 ",%" PRIu64 ",%" PRIu64 ") mem=(%" PRIu64 ",%" PRIu64 ",%" PRIu64 ")\n",
                pos, b, g, r, blue[i], green[i], red[i]);

            mismatches++;
        }
    }

    fclose(inf);
    printf("[APP] Total runtime: %.3f seconds\n", (Global->finishtime - Global->starttime) / 1e6);

    
    f = fopen("/tmp/dsm_exec_time_sec", "w");
    if (mismatches == 0){
        printf("[APP] ✅ Histogram verification successful — all values match.\n");
        if (f) { printf("[APP] Printing into file:/tmp/dsm_exec_time_sec\n"); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
        else printf("Error open file /tmp/dsm_exec_time_sec\n");
    }   
        
    else{
        printf("[APP] ❌ %d mismatches found in histogram verification.\n", mismatches);
        if (f) { fprintf(f, "%.6f\n",-1); fclose(f); }
        else printf("Error open file /tmp/dsm_exec_time_sec\n");
    }


    CHECK_ERROR(munmap(fdata, finfo.st_size) < 0);
    CHECK_ERROR(close(fd) < 0);
    
    free(pid);
    if (dsm_active) {
        for (i = 0; i < num_procs; i++) munmap(arg[i], PAGE_SIZE * 2);
    } else {
        for (i = 0; i < num_procs; i++) {
            // arg[i] has embedded arrays; nothing heap-allocated inside now
        }
    }
    free(arg);
    pthread_attr_destroy(&attr);
    
    return 0;
}
