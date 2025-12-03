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
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>

#include "stddefines.h"
#include "sort-pthread.h"

#define DEFAULT_DISP_NUM 10
#define START_ARRAY_SIZE 2000

typedef struct {
	char* word;
	int count;
   int len;
} wc_count_t;

typedef struct {
   long fpos;
   long flen;
   char *fdata;
   int unit_size;
} wc_data_t;

typedef struct
{
   int length;
   void *data;
   int t_num;
   void *thread_info;
} t_args_t;

enum {
   IN_WORD,
   NOT_IN_WORD
};

typedef struct
{
   int length1;
   int length2;
   int length_out_pos;
   wc_count_t *data1;
   wc_count_t *data2;
   wc_count_t *out;
} merge_data_t;

wc_count_t** words;
int* use_len;
int* length;

void *dsm_wrapper(void *args_in);
void *wordcount_map(void *args_in);
void wordcount_reduce(char *word, int t_num, int len);
int merge_sections(void *args_in);

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

/** mystrcmp()
 *  Comparison function to compare 2 words
 */
int mystrcmp(const void *a, const void *b)
{
    const wc_count_t *w1 = (const wc_count_t *)a;
    const wc_count_t *w2 = (const wc_count_t *)b;
    return strcmp(w1->word, w2->word);
}


/** wordcount_cmp()
 *  Comparison function to compare 2 words
 */
int wordcount_cmp(const void *v1, const void *v2)
{
   wc_count_t* w1 = (wc_count_t*)v1;
   wc_count_t* w2 = (wc_count_t*)v2;

   int i1 = w1->count;
   int i2 = w2->count;

   if (i1 < i2) return 1;
   else if (i1 > i2) return -1;
   else return 0;
}



void *dsm_wrapper(void *args_in){
   
   int idx0, idx1;
   volatile unsigned char *q0, *q1;
   
   t_args_t* args = (t_args_t*)args_in;
   int tid = args->t_num;
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
         }
      }
      pthread_mutex_unlock(&once_lock);
   }

   //gettimeofday(&starttime,0);
   wordcount_map(args_in);
   sort_pthreads(words[tid], use_len[tid], sizeof(wc_count_t), mystrcmp);
   
  
   
   //return;
   splash_barrier(Global, local_threads, tid); //instead of join
   printf("pre merge%d\n", tid);
   
   if (tid == auth_thread) {
      for (int t = auth_thread+1; t < local_threads + auth_thread; t++) {
         
         printf("Auth thread:%d, merging %d to %d, len0:%d, len:%d\n", auth_thread, auth_thread, auth_thread + local_threads, use_len[auth_thread], use_len[t]);
         fprintf(stderr,
               "[PRE-MERGE] t=%d  use_len[0]=%d  use_len[%d]=%d  cap0=%d cap%d=%d\n",
               t, use_len[0], t, use_len[t], length[0], t, length[t]);

         merge_data_t *m = malloc(sizeof(merge_data_t));
         m->length1 = use_len[auth_thread];
         m->length2 = use_len[t];
         m->length_out_pos = auth_thread;
         m->data1 = words[auth_thread];
         m->data2 = words[t];
         m->out   = words[auth_thread];
         
         int out_used = (int)(intptr_t)merge_sections(m);  
         use_len[auth_thread] = out_used;      
         fprintf(stderr,
               "[PRE-MERGE] t=%d  use_len[auth_thread]=%d  use_len[%d]=%d  cap0=%d cap%d=%d\n",
               t, use_len[auth_thread], t, use_len[t], length[auth_thread], t, length[t]);
      }

      // 🔧 nuova fase: consolidamento duplicati in words[0]
      /*sort_pthreads(words[0], use_len[0], sizeof(wc_count_t), mystrcmp);

      int write = 0;
      for (int read = 1; read < use_len[0]; read++) {
         if (strcmp(words[0][write].word, words[0][read].word) == 0) {
               // stessa parola → somma i count
               words[0][write].count += words[0][read].count;
         } else {
               // nuova parola → avanza
               write++;
               if (write != read)
                  words[0][write] = words[0][read];
         }
      }
      use_len[0] = write + 1;*/

      printf("[AUTH:%d] merge complete → total unique words: %d\n", auth_thread, use_len[auth_thread]);

      printf("Writing auth:%d thread info:%p\n", tid, args->thread_info);
      // Write in thread_info page
      args->t_num = use_len[tid];
      printf("Length:%d, use_len:%d\n", length[tid], use_len[tid]);
      memcpy(args->thread_info, args, sizeof(t_args_t));
      

      if (barrier_region && tid ) { //all auth threads except for 0
         // Touch first page for this barrier
         idx0 = current_barrier_index;
         q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
         q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

         fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
                  auth_thread, (void*)q0, idx0);

         // Advance index
         current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

         
         // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
         idx1 = current_barrier_index;
         q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
         q1[0] = (unsigned char)(q1[0] ^ 1);

         fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
                  auth_thread, (void*)q1, idx1);

         current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
      }
      
      /*for( int i=auth_thread; i<auth_thread+local_threads; i++ ){
         printf("Thread %d args %p:\n", i, args);
         printf("  length = %d\n", args->length);
         printf("  data   = %p\n", args->data);
         printf("  t_num  = %d\n", args->t_num);
         printf("  thread_info addr = %p\n\n", args->thread_info);
         if (args->thread_info) {
            printf("Priting values of thread%d, from its words[]=%p\n", i, &(words[i][0]) );
            for (int j = 0; j < DEFAULT_DISP_NUM && j < use_len[i]; j++) {
               wc_count_t *temp = &(words[i][j]);
               printf("The word is %.100s and count is %d len%d\n", temp->word, temp->count, temp->len);
            }
         }
      }*/


   }   
   // sync again so all threads know merging is done
   if(tid) splash_barrier(Global, local_threads, tid);

   return;
}


   

/** wordcount_map()
 * Go through the allocated portion of the file and count the words
 */
void *wordcount_map(void *args_in) 
{
	t_args_t* args = (t_args_t*)args_in;

   char *curr_start, curr_ltr;
   int state = NOT_IN_WORD;
   int i, len;
   assert(args);

   char *data = (char *)(args->data);
   curr_start = data;
   assert(data);

   for (i = 0; i < args->length; i++)
   {
      curr_ltr = toupper(data[i]);
      switch (state)
      {
      case IN_WORD:
         data[i] = curr_ltr;
         if ((curr_ltr < 'A' || curr_ltr > 'Z') && curr_ltr != '\'')
         {
            data[i] = 0;
            len = &data[i] - curr_start; 
			//printf("Th:%d the word is %s, len:%d, %d/%d\n\n", args->t_num, curr_start, len, i, args->length);
         
			wordcount_reduce(curr_start, args->t_num, len);
            state = NOT_IN_WORD;
         }
      break;

      default:
      case NOT_IN_WORD:
         if (curr_ltr >= 'A' && curr_ltr <= 'Z')
         {
            curr_start = &data[i];
            data[i] = curr_ltr;
            state = IN_WORD;
         }
         break;
      }
   }

   // Add the last word
   if (state == IN_WORD)
   {
			data[args->length] = 0;
         len = &data[args->length] - curr_start;
			//printf("\nthe word is %s\n\n",curr_start);
			wordcount_reduce(curr_start, args->t_num, len);
   }
   //free(args);
   return (void *)0;
}

/** wordcount_reduce()
 * Locate the key in the array of word counts and
 * add up the partial sums for each word
 */
void wordcount_reduce(char* word, int t_num, int len) 
{
   int cmp=-1, high = use_len[t_num], low = -1, next;

   // Binary search the array to find the key
   while (high - low > 1)
   {
       next = (high + low) / 2;   
       cmp = strcmp(word, words[t_num][next].word);
       if (cmp == 0)
       {
          high = next;  
          break;
       }
       else if (cmp < 0)
           high = next;
       else
           low = next;
   }

	int pos = high;

   if (pos >= use_len[t_num])
   {
      // at end
      words[t_num][use_len[t_num]].word = word;
	   words[t_num][use_len[t_num]].count = 1;
      words[t_num][use_len[t_num]].len = len;
	   use_len[t_num]++;
	}
   else if (pos < 0)
   {
      // at front
      memmove(&words[t_num][1], words[t_num], use_len[t_num]*sizeof(wc_count_t));
      words[t_num][0].word = word;
	   words[t_num][0].count = 1;
      words[t_num][0].len = len;
	   use_len[t_num]++;
   }
   else if (cmp == 0)
   {
      // match
      words[t_num][pos].count++;
	}
   else
   {
      // insert at pos
      memmove(&words[t_num][pos+1], &words[t_num][pos], (use_len[t_num]-pos)*sizeof(wc_count_t));
      words[t_num][pos].word = word;
	   words[t_num][pos].count = 1;      
      words[t_num][pos].len = len;
	   use_len[t_num]++;
   }

	if(use_len[t_num] == length[t_num])
	{
		length[t_num] *= 2;
	   words[t_num] = (wc_count_t*)realloc(words[t_num],length[t_num]*sizeof(wc_count_t));
	}
}

/** merge_sections()
 * Merge the partial arrays to create the final array that has the
 * word counts
 */
int merge_sections(void *args_in)
{
    merge_data_t* args = (merge_data_t*)args_in;

    wc_count_t *data1 = args->data1;   // words[0] (dest)
    wc_count_t *data2 = args->data2;   // words[i] (src)
    int n1 = args->length1;            // used size 1
    int n2 = args->length2;            // used size 2

    wc_count_t *tmp = (wc_count_t*)malloc((size_t)(n1 + n2) * sizeof(wc_count_t));
    if (!tmp) { perror("malloc tmp merge"); free(args); return (void*)0; }

    int i = 0, j = 0, k = 0;

    while (i < n1 && j < n2) {
        int cmp = strcmp(data1[i].word, data2[j].word);
        if (cmp == 0) {
            tmp[k] = data1[i];
            tmp[k].count = data1[i].count + data2[j].count;
            i++; j++; k++;
        } else if (cmp < 0) {
            tmp[k++] = data1[i++];
        } else {
            tmp[k++] = data2[j++];
        }
    }
    while (i < n1) tmp[k++] = data1[i++];
    while (j < n2) tmp[k++] = data2[j++];

    memcpy(data1, tmp, (size_t)k * sizeof(wc_count_t));
    free(tmp);
    free(args);

    return (void*)(intptr_t)k;   // ✅ return new used length
}

 

int main(int argc, char *argv[]) {
   
   int i, j;
   int fd;
   char * fdata;
   int disp_num;
   struct stat finfo;
   char * fname, * disp_num_str;
   
    int idx0, idx1;
    volatile unsigned char *q0, *q1;
   struct timeval starttime,endtime;

   // Make sure a filename is specified
   if (argv[1] == NULL)
   {
      printf("USAGE: %s <filename> [Top # of results to display]\n", argv[0]);
      exit(1);
   }
   
   fname = argv[1];
   disp_num_str = argv[2];

   printf("Wordcount: Running...\n");
   
   // Read in the file
   CHECK_ERROR((fd = open(fname, O_RDONLY)) < 0);
   // Get the file info (for file length)
   CHECK_ERROR(fstat(fd, &finfo) < 0);
   // Memory map the file
   CHECK_ERROR((fdata = mmap(0, finfo.st_size + 1, 
      PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == NULL);
   
   // Get the number of results to display
   CHECK_ERROR((disp_num = (disp_num_str == NULL) ? 
      DEFAULT_DISP_NUM : atoi(disp_num_str)) <= 0);
   
   // Setup splitter args
   wc_data_t wc_data;
   wc_data.unit_size = 5; // approx 5 bytes per word
   wc_data.fpos = 0;
   wc_data.flen = finfo.st_size;
   wc_data.fdata = fdata;

   dprintf("Wordcount: Calling MapReduce Scheduler Wordcount\n");

   gettimeofday(&starttime,0);

   //wordcount_splitter(&wc_data);

   pthread_attr_t attr;
   pthread_t * tid;


   // DSM init page for mypthread_barrier 
   Global = calloc(1, sizeof(*Global));            // zero out counters too
   pthread_mutex_init(&Global->idlock, NULL);
   pthread_mutex_init(&Global->start.mutex, NULL);
   pthread_cond_init(&Global->start.cv, NULL);
   Global->start.counter = 0;
   Global->start.cycle   = 0;

   const char *env = getenv("DSM");
   if (env) {
      printf("DSM detected, using DSM pthread_barrier\n");
      dsm_init_barrier_pages();
      dsm_active = 1;
      total_threads = atoi(env);  // threads count from DSM env
   } else {
      CHECK_ERROR((total_threads = sysconf(_SC_NPROCESSORS_ONLN)) <= 0);
   }
   dprintf("THe number of processors is %d\n\n", total_threads);

   wc_data_t * data = &wc_data; 
   tid = (pthread_t *)MALLOC(total_threads * sizeof(pthread_t));  

   /* Thread must be scheduled systemwide */
   pthread_attr_init(&attr);
   pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

   words = (wc_count_t**)malloc(total_threads*sizeof(wc_count_t*));
   length = (int*)malloc(total_threads*sizeof(int));
   use_len = (int*)malloc(total_threads*sizeof(int));

   int req_bytes = data->flen / total_threads;
   /* Assign portions of the image to each thread */
   //long curr_pos = (long)(*data_pos);
   FILE *f = fopen("/tmp/ranges.txt", "w");
   if( !f ){
      perror("Failed to open /tmp/ranges.txt");
      exit(-1);
   }
   t_args_t* out ;
   t_args_t* out_0;

   size_t pages_per_thread = 512;

   t_args_t *thread_info = mmap(NULL,
                             total_threads * PAGE_SIZE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                             -1, 0);
   if (thread_info == MAP_FAILED) {
      perror("mmap thread_info");
      exit(1);
   }

   if(f) fprintf(f, "base=%p page_size=%zu num_pages=%zu\n", thread_info, PAGE_SIZE, total_threads);

   for(i=0; i<total_threads; i++)
   {
      // inside for (i = num_procs-1; i >= 0; i--) { ... }
      words[i] = mmap(NULL, PAGE_SIZE * pages_per_thread, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
      if (words[i] == MAP_FAILED) { perror("mmap words[i]"); exit(1); }

      printf("Thread %d, base=%p page_size=%zu num_pages=%zu\n",  i, words[i], (size_t)PAGE_SIZE, pages_per_thread);
      if( f ) fprintf(f, "base=%p page_size=%zu num_pages=%zu\n",  words[i], (size_t)PAGE_SIZE, pages_per_thread);
      fflush(f);  // keep stdout ordered with the next prints

      length[i]  = (PAGE_SIZE * pages_per_thread) / sizeof(wc_count_t);
      use_len[i] = 0;

      out = (t_args_t*)malloc(sizeof(t_args_t));

      long start = data->fpos;               // REAL start for this thread
      out->data  = &data->fdata[start];
   
      int available_bytes = (int)(data->flen - start);
      if (available_bytes < 0) available_bytes = 0;

      out->t_num  = i;
      out->length = (req_bytes < available_bytes) ? req_bytes : available_bytes;
      out->thread_info = (void *)((char *)thread_info + i * PAGE_SIZE);
      // extend to next whitespace so we don't split a word
      for (data->fpos = start + out->length;
         data->fpos < data->flen &&
         data->fdata[data->fpos] != ' '  && data->fdata[data->fpos] != '\t' &&
         data->fdata[data->fpos] != '\r' && data->fdata[data->fpos] != '\n';
         data->fpos++, out->length++) { /* advance */ }

      long end = data->fpos;                 // REAL end for this thread

      printf("TID %d  start=%ld  end=%ld  length=%d  flen=%ld\n", i, start, end, out->length, data->flen);
      fflush(stdout);

      if (i) pthread_create(&tid[i], &attr, dsm_wrapper, (void*)out);
      else out_0 = out;
   }
   dsm_wrapper((void*)out_0);
   
   //tid 0 should arrive here after merging its local threads, to sync with remotes
   if (barrier_region ) {
      // Touch first page for this barrier
      idx0 = current_barrier_index;
      q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
      q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

      fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
               auth_thread, (void*)q0, idx0);

      // Advance index
      current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
      
      printf("\n--- Thread info region dump ---\n");
      for (i = 1; i < total_threads; i++) {
         t_args_t *info = (t_args_t *)((char *)thread_info + i * PAGE_SIZE);

         printf("Thread %d info %p:\n", i, info);
         printf("  length = %d\n", info->length);
         printf("  data   = %p\n", info->data);
         printf("  t_num  = %d\n", info->t_num);
         printf("  thread_info addr = %p\n\n", info->thread_info);

         if (info->thread_info) {
           for (int k = 0; k < pages_per_thread; k++) {
               volatile char *addr = (volatile char *)words[i] + (size_t)k * PAGE_SIZE;
               volatile char tmp = *addr;
               (void)tmp;
               //fprintf(stderr, "[TOUCH] thread %d page %d at %p\n", i, k, (void*)addr);
            }
            use_len[i] = info->t_num;
            printf("Priting values of thread%d, from its words[]=%p\n", i, &(words[i][0]) );
            for (j = 0;  j < use_len[i]; j++) {
               wc_count_t *temp = &(words[i][j]);
               *(temp->word + temp->len ) = '\0';
               for (int k = 0; k < temp->len; k++) {
                  temp->word[k] = toupper((unsigned char)temp->word[k]);
               }
               printf("The word is %.100s and count is %d, len:%d\n", temp->word, temp->count, temp->len);
            }

            fprintf(stderr, "[PRE-MERGE] t=%d  use_len[0]=%d  use_len[%d]=%d  cap0=%d cap%d=%d\n", 
            i, use_len[0], i, use_len[i], length[0], i, length[i]);

            merge_data_t *m = malloc(sizeof(merge_data_t));
            m->length1 = use_len[0];
            m->length2 = use_len[i];
            m->length_out_pos = 0;
            m->data1 = words[0];
            m->data2 = words[i];
            m->out   = words[0];
            
            int out_used = (int)(intptr_t)merge_sections(m);  
            use_len[0] = out_used;      
         
            printf("Auth thread:%d, merging %d to %d, starter use_len[0]:%d\n", 0, 0, i,  use_len[0]);
             
            /*
            merge_data_t *m = malloc(sizeof(merge_data_t));
            use_len[i] = info->t_num;
            m->length1 = use_len[0];
            m->length2 = use_len[i];
            m->length_out_pos = 0;
            m->data1 = words[0];
            m->data2 = words[i];
            m->out   = words[0];
            int out_used = (int)(intptr_t)merge_sections(m);   
            use_len[0] = out_used;    
            
                     
            // ---- Debug dump before merge ----
            fprintf(stderr, "\n[MERGE DEBUG] ==============================\n");
            fprintf(stderr, "[AUTH:%d] Preparing merge with thread %d\n", auth_thread, i);
            fprintf(stderr, "  use_len[0]        = %d\n", use_len[0]);
            fprintf(stderr, "  info->t_num       = %d (remote valid entries)\n", info->t_num);
            fprintf(stderr, "  length[0] (cap1)  = %d\n", length[0]);
            fprintf(stderr, "  length[%d] (cap2)  = %d\n", i, length[i]);
            fprintf(stderr, "  m->length1        = %d\n", m->length1);
            fprintf(stderr, "  m->length2        = %d\n", m->length2);
            fprintf(stderr, "  m->data1 (words0) = %p\n", (void*)m->data1);
            fprintf(stderr, "  m->data2 (words%d) = %p\n", i, (void*)m->data2);
            fprintf(stderr, "  m->out            = %p\n", (void*)m->out);
            */

         }
      }

      //Now we have the pages that we need with the words sorted alfabetically

      
      // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
      idx1 = current_barrier_index;
      q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
      q1[0] = (unsigned char)(q1[0] ^ 1);

      fprintf(stderr, "[APP] auth_thread %d wroote to barrier page %p (index=%d)\n",
               auth_thread, (void*)q1, idx1);

      current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
   }
   splash_barrier(Global, local_threads, tid);
   

   printf("Words counted\n");
   
   printf("Word Count: Completed %ld\n",(endtime.tv_sec - starttime.tv_sec));
   sort_pthreads(words[0], use_len[0], sizeof(wc_count_t), wordcount_cmp);
   gettimeofday(&starttime,0);

   /*for (i = 0; i < total_threads; i++) {
      t_args_t *info = (t_args_t *)((char *)thread_info + i * PAGE_SIZE);

      printf("Thread %d info %p:\n", i, info);
      printf("  length = %d\n", info->length);
      printf("  data   = %p\n", info->data);
      printf("  t_num  = %d\n", info->t_num);
      printf("  thread_info addr = %p\n\n", info->thread_info);
      use_len[i] = info->t_num;
      if (info->thread_info) {
         printf("Priting values of thread%d, from its words[]=%p\n", i, &(words[i][0]) );
         for (j = 0; j < DEFAULT_DISP_NUM && j < use_len[i]; j++) {
            wc_count_t *temp = &(words[i][j]);
            *(temp->word + temp->len ) = '\0';
            printf("The word is %.100s and count is %d, len:%d\n", temp->word, temp->count, temp->len);
         }
      }
   }*/

   
   Global->finishtime = now_us();
   gettimeofday(&endtime,0);

	dprintf("Word Count: Sorting Completed %ld\n",(endtime.tv_sec - starttime.tv_sec));
   for (j = 0; j < DEFAULT_DISP_NUM && j < use_len[0]; j++) {
      wc_count_t *temp = &(words[0][j]);
      printf("The word is %.100s and count is %d, len:%d\n", temp->word, temp->count, temp->len);
   }
   printf("\nTotal unique words: %d\n", use_len[0]);
   
    printf("[APP] Total runtime: %.3f seconds\n", (Global->finishtime - Global->starttime) / 1e6);

   free(use_len);
   
   free(words);

   CHECK_ERROR(munmap(fdata, finfo.st_size + 1) < 0);
   CHECK_ERROR(close(fd) < 0);

   return 0;
}
