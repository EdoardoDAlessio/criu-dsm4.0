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
#include <string.h>
#include <math.h>
#include <pthread.h>

#include "stddefines.h"
#include "map_reduce.h"

#define DEF_NUM_POINTS 100000
#define DEF_NUM_MEANS 100
#define DEF_DIM 3
#define DEF_GRID_SIZE 1000

#define false 0
#define true 1

int num_points; // number of vectors
int dim;       // Dimension of each vector
int num_means; // number of clusters
int grid_size; // size of each dimension of vector space
//int modified;
int num_pts = 0;
   
int **points;
int **means;
int *clusters;

   
typedef struct {
   int start_idx;
   int num_pts;
   int *sum;
   int tid;
   size_t bytes;
} thread_argument;

thread_argument *args;

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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

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
int idx0, idx1;
volatile unsigned char *q0, *q1;
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


/** dump_points()
 *  Helper function to print out the points
 */
void dump_points(int **vals, int rows)
{
   int i, j;
   for (i = 0; i < rows; i++) 
   {
      for (j = 0; j < dim; j++)
      {
         dprintf("%5d ",vals[i][j]);

      }
      dprintf("\n");
   }
}

#if 1
void dump_points_check(int **vals, int rows)
{
    char outname[512];
    char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/kmeans";

    snprintf(outname, sizeof(outname),
             "%s/kmeans_p%d_d%d_c%d_s%d_check.bin",
             dir, num_points, dim, num_means, grid_size);

    FILE *inf = fopen(outname, "rb");
    if (!inf) {
        printf("Filename: %s\n", outname);
        perror("fopen check");
        exit(1);
    }

    printf("[CHECK] Reading binary check file: %s\n", outname);

    int mismatch = 0;

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < dim; j++) {
            int read_val;
            size_t n = fread(&read_val, sizeof(int), 1, inf);
            if (n != 1) {
                fprintf(stderr,
                        "[CHECK] Error reading value at row %d col %d\n",
                        i, j);
                fclose(inf);
                exit(1);
            }

            if (read_val != vals[i][j]) {
                mismatch++;
                if (mismatch <= 20) {
                    printf("  MISMATCH at row %d col %d: file=%d expected=%d\n",
                           i, j, read_val, vals[i][j]);
                }
            }
        }
    }

    fclose(inf);

    FILE *f = fopen("/tmp/dsm_exec_time_sec", "w");

    if (mismatch == 0){
        printf("[APP] ✅ Kmeans verification successful — all values match.\n");
        if (f) { printf("[APP] Printing into file:/tmp/dsm_exec_time_sec\n"); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
        else printf("Error open file /tmp/dsm_exec_time_sec\n");
    }
    else{
        printf("[APP] ❌ %d mismatches found in kmeans verification.\n", mismatch);
        if (f) { fprintf(f, "%.6f\n", -1); fclose(f); }
    }
        
}


#elif 1
void dump_points_check(int **vals, int rows)
{
    size_t total_ints = (size_t)rows * dim;

    char outname[512];
    char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/kmeans";

    snprintf(outname, sizeof(outname),
             "%s/kmeans_p%d_d%d_c%d_s%d_check.bin",
             dir, num_points, dim, num_means, grid_size);

    FILE *inf = fopen(outname, "rb");
    if (!inf) {
        printf("Filename: %s\n", outname);
        perror("fopen check");
        exit(1);
    }

    printf("[CHECK] Reading binary check file: %s\n", outname);

    /* allocate buffer for comparison */
    int *buffer = malloc(total_ints * sizeof(int));
    if (!buffer) {
        perror("malloc buffer");
        exit(1);
    }

    /* read entire file */
    size_t n = fread(buffer, sizeof(int), total_ints, inf);
    fclose(inf);

    if (n != total_ints) {
        fprintf(stderr,
                "[CHECK] ERROR: file size mismatch: read %zu ints, expected %zu\n",
                n, total_ints);
        exit(1);
    }

    /* compare */
    size_t mismatch = 0;

    for (size_t idx = ; idx < total_ints; idx++) {
        if (buffer[idx] != vals[0][idx]) {
            size_t row = idx / dim;
            size_t col = idx % dim;

            mismatch++;
            if (mismatch < 20) {
                printf("  MISMATCH at row %zu col %zu: file=%d expected=%d\n",
                       row, col, buffer[idx], vals[0][idx]);
            }
        }
    }

    free(buffer);

    if (mismatch == 0) {
        printf("[CHECK] Verification passed — all %zu values match.\n", total_ints);
    } else {
        printf("[CHECK] Verification FAILED — %zu mismatches.\n", mismatch);
    }
}


#else

void dump_points_check(int **vals, int rows)
{
   int i, j;
    int mismatch = 0;
    char outname[512];
    char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/kmeans";
    snprintf(outname, sizeof(outname), "%s/kmeans_p%d_d%d_c%d_s%d_check.bin", dir, num_points, dim, num_means, grid_size);
    FILE *inf = fopen(outname, "r");
    if (!inf) {
        printf("Filename:%s\n", outname);
        perror("fopen check");
        exit(1);
    }

    /* optional: allocate buffer to read back into */
    int read_val;
    printf("[CHECK] Reading results from %s\n", outname);

    for (i = 0; i < rows; i++) {
        for (j = 0; j < dim; j++) {
            if (fscanf(inf, "%d", &read_val) != 1) {
                fprintf(stderr,
                        "Error reading value at row %d col %d\n", i, j);
                exit(1);
            }

            /* print or compare */
            printf("%5d ", read_val);

            /* if you want to verify correctness */
            if (read_val != vals[i][j]){
                mismatch++;
                printf("  <-- mismatch (expected %d)", vals[i][j]);
            }
        }
        printf("\n");
    }

    fclose(inf);
    if (mismatch == 0) {
        printf("[CHECK] Verification passed — all values match.\n");
    } else {
        printf("[CHECK] Verification failed — %d mismatches found.\n", mismatch);
    }
}
#endif

/** parse_args()
 *  Parse the user arguments
 */
void parse_args(int argc, char **argv) 
{
   int c;
   extern char *optarg;
   extern int optind;
   
   num_points = DEF_NUM_POINTS;
   num_means = DEF_NUM_MEANS;
   dim = DEF_DIM;
   grid_size = DEF_GRID_SIZE;
   
   while ((c = getopt(argc, argv, "d:c:p:s:")) != EOF) 
   {
      switch (c) {
         case 'd':
            dim = atoi(optarg);
            break;
         case 'c':
            num_means = atoi(optarg);
            break;
         case 'p':
            num_points = atoi(optarg);
            break;
         case 's':
            grid_size = atoi(optarg);
            break;
         case '?':
            printf("Usage: %s -d <vector dimension> -c <num clusters> -p <num points> -s <grid size>\n", argv[0]);
            exit(1);
      }
   }
   
   if (dim <= 0 || num_means <= 0 || num_points <= 0 || grid_size <= 0) {
      printf("Illegal argument value. All values must be numeric and greater than 0\n");
      exit(1);
   }
   
   printf("Dimension = %d\n", dim);
   printf("Number of clusters = %d\n", num_means);
   printf("Number of points = %d\n", num_points);
   printf("Size of each dimension = %d\n", grid_size);   
}

/** generate_points()
 *  Generate the points
 */
void generate_points(int **pts, int size) 
{   
   int i, j;
   
   for (i=0; i<size; i++) 
   {
      for (j=0; j<dim; j++) 
      {
         pts[i][j] = rand() % grid_size;
      }
   }
}

/** get_sq_dist()
 *  Get the squared distance between 2 points
 */
static inline unsigned int get_sq_dist(int *v1, int *v2)
{
   int i;
   
   unsigned int sum = 0;
   for (i = 0; i < dim; i++) 
   {
      sum += ((v1[i] - v2[i]) * (v1[i] - v2[i])); 
   }
   return sum;
}

/** add_to_sum()
 *	Helper function to update the total distance sum
 */
void add_to_sum(int *sum, int *point)
{
   int i;
   
   for (i = 0; i < dim; i++)
   {
      sum[i] += point[i];   
   }   
}

#if 1
/** find_clusters()
 *  Assign each point in this thread's slice to its nearest cluster.
 */
void *find_clusters(void *arg) 
{
    thread_argument *t_arg = (thread_argument *)arg;
    printf("[find_clusters] T%d working on points [%d, %d)\n",
           t_arg->tid, t_arg->start_idx, t_arg->start_idx + t_arg->num_pts);

    int start = t_arg->start_idx;
    int end   = start + t_arg->num_pts;
    int *base     = (int *)t_arg->sum;
    int *mod_ptr  = &base[0];
    *mod_ptr = 0;   //reset
    
    for (int i = start; i < end; i++) {
        unsigned int min_dist = get_sq_dist(points[i], means[0]);
        int min_idx = 0;

        for (int j = 1; j < num_means; j++) {
            unsigned int cur_dist = get_sq_dist(points[i], means[j]);
            if (cur_dist < min_dist) {
                min_dist = cur_dist;
                min_idx  = j;
            }
        }

        if (clusters[i] != min_idx) {
            clusters[i] = min_idx;
            //modified = true;
            *mod_ptr = true;
        }
    }

    return NULL;
}

/** calc_means()
 *  Each thread builds local partial sums and counts for its points.
 *  Buffer layout in t_arg->sum:
 *    [0 .. num_means*dim-1]      -> local_sum  (ints)
 *    [num_means*dim .. end]      -> local_count (ints)
 *  Main thread merges all after join.
 */
void *calc_means(void *arg)
{
    thread_argument *a = (thread_argument *)arg;

    printf("[calc_means] T%d using buffer %p (%zu bytes)\n",
           a->tid, (void *)a->sum, a->bytes);

    // derive local_sum and local_count views from mmap buffer
    //storing local modified then when we merge we look if there's a true!        
    int *local_sum   = a->sum + 1;                      // size = num_means * dim
    int *local_count = a->sum + (num_means * dim)+ 1;   // size = num_means

    // sanity check
    size_t need_bytes = ((size_t)num_means * (size_t)dim + (size_t)num_means) * sizeof(int) + sizeof(int);
    if (a->bytes < need_bytes) {
        fprintf(stderr, "[calc_means][T%d] ERROR: buffer too small (%zu < %zu)\n",
                a->tid, a->bytes, need_bytes);
        return NULL;
    }

    memset(local_sum,   0, (size_t)num_means * (size_t)dim * sizeof(int));
    memset(local_count, 0, (size_t)num_means * sizeof(int));

    int start = a->start_idx;
    int end   = start + a->num_pts;

    for (int i = start; i < end; i++) {
        int c = clusters[i];  // cluster index for this point
        if (c < 0 || c >= num_means) continue; // safety guard

        local_count[c]++;

        // sum point coordinates: local_sum[c*dim + d] += points[i][d]
        int base = c * dim;
        for (int d = 0; d < dim; d++)
            local_sum[base + d] += points[i][d];
    }

    return NULL;
}

#else
/** find_clusters()
 *  Find the cluster that is most suitable for a given set of points
 */
void *find_clusters(void *arg) 
{
   thread_argument *t_arg = (thread_argument *)arg;
    printf("[find_clusters] T%d working on points [%d, %d)\n",
           t_arg->tid, t_arg->start_idx, t_arg->start_idx + t_arg->num_pts);
   int i, j;
   unsigned int min_dist, cur_dist;
   int min_idx;
   int start_idx = t_arg->start_idx;
   int end_idx = start_idx + t_arg->num_pts;
   
   for (i = start_idx; i < end_idx; i++) 
   {
      min_dist = get_sq_dist(points[i], means[0]);
      min_idx = 0; 
      for (j = 1; j < num_means; j++)
      {
         cur_dist = get_sq_dist(points[i], means[j]);
         if (cur_dist < min_dist) 
         {
            min_dist = cur_dist;
            min_idx = j;   
         }
      }
      
      if (clusters[i] != min_idx) 
      {
         clusters[i] = min_idx;
         modified = true;
      }
   }
   
   return (void *)0;   
}

/** calc_means()
 *  Compute the means for the various clusters
 */
void *calc_means(void *arg)
{

    thread_argument *a = arg;
    printf("[calc_means] T%d using buffer %p (%zu bytes)\n",
           a->tid, a->sum, a->bytes);
   int i, j, grp_size;
   int *sum;
   thread_argument *t_arg = (thread_argument *)arg;
   int start_idx = t_arg->start_idx;
   int end_idx = start_idx + t_arg->num_pts;
   
   sum = t_arg->sum;
   
   for (i = start_idx; i < end_idx; i++) 
   {
      memset(sum, 0, dim * sizeof(int));
      grp_size = 0;
      
      for (j = 0; j < num_points; j++)
      {
         if (clusters[j] == i) 
         {
            add_to_sum(sum, points[j]);
            grp_size++;
         }   
      }
      
      for (j = 0; j < dim; j++)
      {
         //dprintf("div sum = %d, grp size = %d\n", sum[j], grp_size);
         if (grp_size != 0)
         { 
            means[i][j] = sum[j] / grp_size;
         }
      }       
   }
   free(sum);
   return (void *)0;
}
#endif
int iterations = 0;
int local_modified;


void *dsm_wrapper(void *arg) {
    thread_argument *a = arg;
    int tid = a->tid;

    printf("[T%d] start=%d num_pts=%d buffer=%p (%zu bytes)\n",
           a->tid, a->start_idx, a->num_pts, (void*)a->sum, a->bytes);

    /* DSM init for first thread after restore */
    if (dsm_active) {
        check_halt_file(tid);
        pthread_mutex_lock(&once_lock);
        if (!done) {
            Global->starttime = now_us();
            done = 1;
            
            dump_points(means, num_means);

            FILE *f = fopen("/tmp/restored_threads.txt", "r");
            if (f) {
                if (fscanf(f, "%d", &local_threads) == 1)
                    printf("[APP] Read barrier count from /tmp/restored_threads.txt: %d\n", local_threads);
                else
                    printf("[APP] Failed to parse integer from /tmp/restored_threads.txt, using default count\n");
                fclose(f);
            }

            f = fopen("/tmp/authorized_barrier_thread.txt", "r");
            if (f) {
                if (fscanf(f, "%d", &auth_thread) == 1)
                    printf("auth_thread:%d\n", auth_thread);
                fclose(f);
            } else {
                printf("[APP] Could not open /tmp/authorized_barrier_thread.txt, doing nothing\n");
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&once_lock);
    }

    long long *Gsum = calloc((size_t)num_means * dim, sizeof(long long));
    long long *Gcnt = calloc((size_t)num_means, sizeof(long long));
    if (!Gsum || !Gcnt) {
        fprintf(stderr, "[T%d] ERROR: calloc failed\n", tid);
        return NULL;
    }


    /* ---- main loop ---- */
    while ( 1 ) {
        splash_barrier(Global, local_threads, tid);
        /* reset modified once per iteration, synchronized */
        if (tid == auth_thread){
            local_modified = 0;
        } 
    
        printf("TID:%d Iteration:%d\n", tid, iterations);

        /* phase 1: assign clusters */
        find_clusters(a);

        /* phase 2: compute local partial means */
        calc_means(a);


        splash_barrier(Global, local_threads, tid); //sync LOCAL threads
        if (barrier_region && tid == auth_thread ) {
            // Touch first page for this barrier
            idx0 = current_barrier_index;
            q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
            q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

            fprintf(stderr, "[APP] main %d wrote to barrier page %p (index=%d)\n",
                auth_thread, (void*)q0, idx0);

            // Advance index
            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

        
            /* phase 3: merge results on every node */
            if ( tid == auth_thread ) {
                memset(Gsum, 0, sizeof(long long) * (size_t)num_means * (size_t)dim);
                memset(Gcnt, 0, sizeof(long long) * (size_t)num_means);

                for (int t = 0; t < total_threads; t++) {
                    int *base     = (int *)args[t].sum;
                    int *mod_ptr  = &base[0];

                    if (*mod_ptr) {
                        //modified = true;//if any node has modified flag true, then everyone has to do the loop again
                        local_modified = 1;
                        //*mod_ptr = 0;   //reset
                    }


                    int *sum_t   = args[t].sum + 1;
                    int *count_t = args[t].sum + (num_means * dim) + 1;

                    for (int c = 0; c < num_means; c++) {
                        Gcnt[c] += count_t[c];
                        int base = c * dim;
                        for (int d = 0; d < dim; d++)
                            Gsum[base + d] += sum_t[base + d];
                    }
                }

                /* update global means */
                for (int c = 0; c < num_means; c++) {
                    if (Gcnt[c] > 0) {
                        for (int d = 0; d < dim; d++)
                            means[c][d] = (int)(Gsum[c * dim + d] / Gcnt[c]);
                    } else {
                        /* preserve old centroid if cluster is empty */
                        printf("[WARN][T%d] cluster %d has 0 points, keeping old mean\n", tid, c);
                    }
                }

                iterations++;
                dump_points(means, num_means);
            }
            
            // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] auth_thread %d second barrier page %p (index=%d)\n",
                auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }
        splash_barrier(Global, local_threads, tid);
        printf("Post barrier\n");
        // also enforce visibility of local_modified before other threads continue

        printf("TH%d local_modified%d\n", tid, local_modified);
        /* check convergence */
        if (!local_modified)
            break;
    }

    free(Gsum);
    free(Gcnt);
    return NULL;
}




int main(int argc, char **argv)
{
   
   int num_procs, curr_point;
   int i;
   pthread_t *pid;
   pthread_attr_t attr;
   int num_per_thread, excess; 
   
   parse_args(argc, argv);   
   
   points = (int **)malloc(sizeof(int *) * num_points);
   for (i=0; i<num_points; i++) 
   {
      points[i] = (int *)malloc(sizeof(int) * dim);
   }
   dprintf("Generating points\n");
   generate_points(points, num_points);

   
   means = (int **)malloc(sizeof(int *) * num_means);
   for (i=0; i<num_means; i++) 
   {
      means[i] = (int *)malloc(sizeof(int) * dim);
   }
   dprintf("Generating means\n");
   generate_points(means, num_means);
 
   clusters = (int *)malloc(sizeof(int) * num_points);
   memset(clusters, -1, sizeof(int) * num_points);
   

    dump_points(means, num_means);
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
      total_threads = num_procs;
      printf("Num threads:%d\n", num_procs);
   } else {
      CHECK_ERROR((num_procs = sysconf(_SC_NPROCESSORS_ONLN)) <= 0);
   }
   CHECK_ERROR( (pid = (pthread_t *)malloc(sizeof(pthread_t) * num_procs)) == NULL);
   
   //modified = true; 
   
   printf("Starting iterative algorithm\n");
   
   /* Create the threads to process the distances between the various
   points and repeat until modified is no longer valid */


   pid = (pthread_t *)MALLOC(num_procs * sizeof(pthread_t));
    
   CHECK_ERROR((args = (thread_argument *)malloc(sizeof(thread_argument ) * num_procs)) == NULL);
    
   
   dump_points(means, num_means);

   /* --- Divide work here --- */
   num_per_thread = num_points / num_procs;
   excess         = num_points % num_procs;
   curr_point     = 0;
   long ps = sysconf(_SC_PAGESIZE);

   
   /* Compute how much buffer space each thread needs */
   size_t bytes_needed = 
    (size_t)num_means * dim * sizeof(int) +   // local_sum
    (size_t)num_means * sizeof(int) +          // local_count
    sizeof(int); //for storing modified 
   // round up to full pages, but allocate at least 2 pages for DSM flexibility
   size_t bytes_per_thread = ((bytes_needed + ps - 1) / ps) * ps;
   if (bytes_per_thread < 2 * ps) bytes_per_thread = 2 * ps;   // ensure >= 2 pages
   
   printf("[INFO] Each thread needs ~%zu bytes -> allocating %zu bytes (%zu pages)\n",
       bytes_needed, bytes_per_thread, bytes_per_thread / ps);

   
   
    FILE *f = fopen("/tmp/ranges.txt", "w");

    for (i = 0; i < num_procs; i++) {
        args[i].tid       = i;
        args[i].start_idx = curr_point;
        args[i].num_pts   = num_per_thread + (i < excess ? 1 : 0);
        curr_point       += args[i].num_pts;

        args[i].bytes = bytes_per_thread;
        args[i].sum = mmap(NULL, bytes_per_thread,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK_ERROR(args[i].sum == MAP_FAILED);
        memset(args[i].sum, 0, bytes_per_thread);

        printf("[MAIN] T%d start=%d num_pts=%d buf=%p (%zu bytes, %zu pages)\n",
            args[i].tid, args[i].start_idx, args[i].num_pts,
            args[i].sum, args[i].bytes, args[i].bytes / ps);
        if(i) CHECK_ERROR((pthread_create(&(pid[i]), &attr, dsm_wrapper, &args[i])) != 0);

                
        if ( f ){
            fprintf(f, "base=%p page_size=%zu num_pages=%d\n", args[i].sum, ps, args[i].bytes / ps);
            fflush(f);
            printf("Thread %d, base=%p page_size=%zu num_pages=%d\n", i, args [i].sum, ps, args[i].bytes / ps);
        }

    }

    
    dsm_wrapper(&args[0]);

    
    Global->finishtime = now_us();
   /* Cleanup mmaps */
   for (i = 0; i < num_procs; i++)
      munmap(args[i].sum, args[i].bytes);

   free(args);
   free(pid);



   dprintf("\n\nFinal means:\n");
   dump_points_check(means, num_means);
    
    printf("[APP] Total runtime: %.3f seconds\n", (Global->finishtime - Global->starttime) / 1e6);

   for (i = 0; i < num_points; i++) 
      free(points[i]);
   free(points);
   
   for (i = 0; i < num_means; i++) 
   {
      free(means[i]);
   }
   free(means);
   free(clusters);

   return 0;
}
