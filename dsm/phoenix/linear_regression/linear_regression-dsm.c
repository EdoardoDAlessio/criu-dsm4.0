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

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "stddefines.h"

typedef struct {
   char x;
   char y;
} POINT_T;

typedef struct
{
    int tid;
    POINT_T *points;
    int num_elems;
    long long SX;
    long long SY; 
    long long SXX;
    long long SYY; 
    long long SXY;
} lreg_args;




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
int done = 0;

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





/* linear_regression_pthread
 * 
 */
void *linear_regression_pthread(void *args_in) 
{
   lreg_args* args =(lreg_args*)args_in;
   int i;

   int tid = args->tid;
   int idx0, idx1;
   volatile unsigned char *q0, *q1;


   if( dsm_active){
      check_halt_file(tid);

      pthread_mutex_lock(&once_lock);
      if( !done ){
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
                  return;
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
                  return;
               }
               fflush(stdout);


               /*const char *env = getenv("DSM");
               if (env) {
                  local_threads = atoi(env); 
                  printf("DSM detected, local_threads:%d\n", local_threads);
               }
               env = getenv("AUTH");
               if (env) {
                  local_threads = atoi(env); 
                  printf("AUTH detected, auth_thread:%d\n", auth_thread);
               }else auth_thread = tid;*/
         }
      }
      pthread_mutex_unlock(&once_lock);
   }
   /* 🟢 Print the addresses of each variable (and of the struct itself) */
   printf("[T%lu] args=%p SX=%p SXX=%p SY=%p SYY=%p SXY=%p\n",
         tid,
         (void *)args,
         (void *)&args->SX,
         (void *)&args->SXX,
         (void *)&args->SY,
         (void *)&args->SYY,
         (void *)&args->SXY);
   
   args->SX = 0;
   args->SXX = 0;
   args->SY  = 0;
   args->SYY = 0;
   args->SXY = 0;

    // ADD UP RESULTS
   for (i = 0; i < args->num_elems; i++)
   {
      //Compute SX, SY, SYY, SXX, SXY
      args->SX  += args->points[i].x;
      args->SXX += args->points[i].x*args->points[i].x;
      args->SY  += args->points[i].y;
      args->SYY += args->points[i].y*args->points[i].y;
      args->SXY += args->points[i].x*args->points[i].y;
   }

   if(dsm_active && tid ){
      splash_barrier(Global, local_threads, tid); //sync LOCAL threads
      if (barrier_region && tid == auth_thread ) {
         // Touch first page for this barrier
         idx0 = current_barrier_index;
         q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
         q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

         fprintf(stderr, "[APP] auth_thread %d wrote to barrier page %p (index=%d)\n",
                  auth_thread, (void*)q0, idx0);

         // Advance index
         current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

         
         // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
         idx1 = current_barrier_index;
         q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
         q1[0] = (unsigned char)(q1[0] ^ 1);

         fprintf(stderr, "[APP] auth_thread %d wrote to barrier page %p (index=%d)\n",
                  auth_thread, (void*)q1, idx1);

         current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
      }
      splash_barrier(Global, local_threads, tid);
   }

   return (void *)0;
}


int main(int argc, char *argv[])
{
   int fd;
   char * fdata;
   char * fname;
   struct stat finfo;
   
   pthread_t *pid;
    
   int req_units, num_threads, num_procs, i;
   pthread_attr_t attr;
   lreg_args** tid_args;
   
   int idx0, idx1;
   volatile unsigned char *q0, *q1;

   // Make sure a filename is specified
   if (argv[1] == NULL)
   {
      printf("USAGE: %s <filename>\n", argv[0]);
      exit(1);
   }
   
   fname = argv[1];

   // Read in the file
   CHECK_ERROR((fd = open(fname, O_RDONLY)) < 0);
   // Get the file info (for file length)
   CHECK_ERROR(fstat(fd, &finfo) < 0);
   // Memory map the file
   CHECK_ERROR((fdata = mmap(0, finfo.st_size + 1, 
      PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == NULL);

   
   
   // DSM init page for mypthread_barrier 
   Global = (struct GlobalMemory *) malloc(sizeof(struct GlobalMemory));;
   const char *env = getenv("DSM");
   if (env) {
      printf("DSM detected, using DSM pthread_barrier\n");
      dsm_init_barrier_pages();
      dsm_active = 1;
      num_procs = atoi(env);  // threads count from DSM env
   } else {
      CHECK_ERROR((num_procs = sysconf(_SC_NPROCESSORS_ONLN)) <= 0);
   }


   printf("The number of threads is %d\n\n", num_procs);

   pthread_attr_init(&attr);
   pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

   num_threads = num_procs;

   printf("Linear Regression P-DSM: Running...\n");


   POINT_T *points = (POINT_T*)fdata;
   long long n = (long long) finfo.st_size / sizeof(POINT_T);

   req_units = n / num_threads;
   

   // Allocate one page per thread for DSM / userfaultfd visibility
   tid_args = calloc(num_threads, sizeof(lreg_args *));
   
   CHECK_ERROR((pid = (pthread_t *)malloc(sizeof(pthread_t) * num_procs)) == NULL);
   CHECK_ERROR(tid_args == NULL);

   size_t page_size = sysconf(_SC_PAGESIZE);
   FILE *f = fopen("/tmp/ranges.txt", "w");

   for (i = 0; i < num_threads; i++) {
      // One private (or shared) page per thread
      tid_args[i] = mmap(NULL, page_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1, 0);
      if (tid_args[i] == MAP_FAILED) {
         perror("mmap tid_args[i]");
         exit(1);
      }
      

      // Log the mapping (for DSM tracking/debug)
      if (f) {
         fprintf(f, "base=%p page_size=%zu num_pages=%d\n",
                  tid_args[i], page_size, 1);
         fflush(f);
         printf("Thread %d, base=%p page_size=%zu num_pages=%d\n", i, tid_args[i], page_size, 1);
      }

      // Initialize struct
      memset(tid_args[i], 0, sizeof(lreg_args));
      tid_args[i]->points = &points[i * req_units];
      tid_args[i]->num_elems = (i == num_threads - 1)
                                 ? n - i * req_units
                                 : req_units;
      tid_args[i]->tid = i;
      // Launch thread
      if(i) CHECK_ERROR(pthread_create(&pid[i], &attr,
                                 linear_regression_pthread,
                                 (void *)tid_args[i]) != 0);
   }
   linear_regression_pthread(tid_args[0]);

   if (f) fclose(f);
   

   long long SX_ll = 0, SY_ll = 0, SXX_ll = 0, SYY_ll = 0, SXY_ll = 0;

   /* Barrier, wait for all threads to finish */
   if(dsm_active){
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
                volatile char *p = (volatile char *)tid_args[i];
                char h = (unsigned char)(p[0] ^ 1);     
                fprintf(stderr, "[APP] accessed page %p\n", p);
            }
            printf("==========================\n\n");
            
            // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] main %d wrote to barrier page %p (index=%d)\n",
                   auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }
        splash_barrier(Global, local_threads, 0);
    }else{
      for (i = 0; i < num_threads; i++){
         int ret_val;
         CHECK_ERROR(pthread_join(tid_args[i]->tid, (void **)(void*)&ret_val) != 0);
         CHECK_ERROR(ret_val != 0);

         SX_ll += tid_args[i]->SX;
         SY_ll += tid_args[i]->SY; 
         SXX_ll += tid_args[i]->SXX; 
         SYY_ll += tid_args[i]->SYY; 
         SXY_ll += tid_args[i]->SXY;
      }
   }

   for (i = 0; i < num_threads; i++){
      SX_ll += tid_args[i]->SX;
      SY_ll += tid_args[i]->SY; 
      SXX_ll += tid_args[i]->SXX; 
      SYY_ll += tid_args[i]->SYY; 
      SXY_ll += tid_args[i]->SXY;
   }
   
   Global->finishtime = now_us();
   
   /*
   printf("Linear Regression P-dsm Results:\n");
   printf("\tSX   = %lld\n", SX_ll);
   printf("\tSY   = %lld\n", SY_ll);
   printf("\tSXX  = %lld\n", SXX_ll);
   printf("\tSYY  = %lld\n", SYY_ll);
   printf("\tSXY  = %lld\n", SXY_ll);*/

   free(tid_args);

   double a, b, xbar, ybar, r2;
   double SX = (double)SX_ll;
   double SY = (double)SY_ll;
   double SXX= (double)SXX_ll;
   double SYY= (double)SYY_ll;
   double SXY= (double)SXY_ll;

   b = (double)(n*SXY - SX*SY) / (n*SXX - SX*SX);
   a = (SY_ll - b*SX_ll) / n;
   xbar = (double)SX_ll / n;
   ybar = (double)SY_ll / n;
   r2 = (double)(n*SXY - SX*SY) * (n*SXY - SX*SY) / ((n*SXX - SX*SX)*(n*SYY - SY*SY));

   /*
   printf("Linear Regression P-dsm Results:\n");
   printf("\ta    = %lf\n", a);
   printf("\tb    = %lf\n", b);
   printf("\txbar = %lf\n", xbar);
   printf("\tybar = %lf\n", ybar);
   printf("\tr2   = %lf\n", r2);
   printf("\tSX   = %lld\n", SX_ll);
   printf("\tSY   = %lld\n", SY_ll);
   printf("\tSXX  = %lld\n", SXX_ll);
   printf("\tSYY  = %lld\n", SYY_ll);
   printf("\tSXY  = %lld\n", SXY_ll);*/


   char outname[512];
   snprintf(outname, sizeof(outname), "%s_check", fname);

   /* Verify the results file contents against current computation */
   FILE *inf = fopen(outname, "r");
   if (!inf) {
      perror("fopen verify");
      exit(1);
   }

   char header[256];
   fgets(header, sizeof(header), inf); // Skip the "Linear Regression ..." line
   fgets(header, sizeof(header), inf); // Skip the column header line

   /* Read the saved values */
   double a_f, b_f, xbar_f, ybar_f, r2_f;
   long long SX_f, SY_f, SXX_f, SYY_f, SXY_f;

   if (fscanf(inf, "%lf%lf%lf%lf%lf%lld%lld%lld%lld%lld",
            &a_f, &b_f, &xbar_f, &ybar_f, &r2_f,
            &SX_f, &SY_f, &SXX_f, &SYY_f, &SXY_f) != 10) {
      fprintf(stderr, "Error: malformed results file %s\n", outname);
      fclose(inf);
      exit(1);
   }
   fclose(inf);

   /* Compare each value with current in-memory computation */
   double eps = 1e-6;  // acceptable floating-point tolerance
   
   printf("[APP] Total runtime: %.4f seconds\n", (Global->finishtime - Global->starttime) / 1e6);

   if (fabs(a - a_f) < eps &&
      fabs(b - b_f) < eps &&
      fabs(xbar - xbar_f) < eps &&
      fabs(ybar - ybar_f) < eps &&
      fabs(r2 - r2_f) < eps &&
      SX_ll == SX_f && SY_ll == SY_f &&
      SXX_ll == SXX_f && SYY_ll == SYY_f && SXY_ll == SXY_f)
   {
      printf("✅ Verification passed — results match stored values.\n");
   }
   else {
      printf("❌ Verification failed — mismatch found.\n");
      printf("Current:\n");
      printf("  a=%lf b=%lf xbar=%lf ybar=%lf r2=%lf SX=%lld SY=%lld SXX=%lld SYY=%lld SXY=%lld\n",
            a,b,xbar,ybar,r2,SX_ll,SY_ll,SXX_ll,SYY_ll,SXY_ll);
      printf("Saved:\n");
      printf("  a=%lf b=%lf xbar=%lf ybar=%lf r2=%lf SX=%lld SY=%lld SXX=%lld SYY=%lld SXY=%lld\n",
            a_f,b_f,xbar_f,ybar_f,r2_f,SX_f,SY_f,SXX_f,SYY_f,SXY_f);
   }



   CHECK_ERROR(pthread_attr_destroy(&attr) < 0);
   CHECK_ERROR(munmap(fdata, finfo.st_size + 1) < 0);
   CHECK_ERROR(close(fd) < 0);
   return 0;
}
