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
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <inttypes.h>

#include "map_reduce.h"
#include "stddefines.h"

typedef struct {
    int tid;
    int *matrix_A;
    int *matrix_B;
    int matrix_len;
    int *output;
    int *output_start;
    int *output_end;
    size_t num_pages;
    int start_row, end_row;
} mm_data_t;


typedef struct {
	int x_loc;
	int y_loc;
	int value;
} mm_key_t;



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
int print;

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



void *matrixmult_map(void *args_in);

/** matrixmul_splitter()
 *  Assign a set of rows of the output matrix to each thread
 */
void matrixmult_splitter(void *data_in)
{
    pthread_attr_t attr;
    pthread_t * pid;
    int i, num_procs;

	/* Make a copy of the mm_data structure */
    mm_data_t * data = (mm_data_t *)data_in; 
    mm_data_t **arg;
    /* Check whether the various terms exist */
    assert(data_in);    
    assert(data->matrix_len >= 0);
    assert(data->matrix_A);
    assert(data->matrix_B);
    assert(data->output);
    
    int idx0, idx1;
    volatile unsigned char *q0, *q1;


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

    dprintf("THe number of processors is %d\n", num_procs);

    pid = (pthread_t *)MALLOC(num_procs * sizeof(pthread_t));
    
    CHECK_ERROR((arg = (mm_data_t **)malloc(sizeof(mm_data_t *) * num_procs)) == NULL);
    
    /* Thread must be scheduled systemwide */
    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    const int N = data->matrix_len;
    const size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    int base_rows  = N / num_procs;
    int extra_rows = N % num_procs;
    size_t elem_cursor = 0; 

    /* --- Open log file --- */
    FILE *f = fopen("/tmp/ranges.txt", "w");
    if (!f) perror("fopen /tmp/ranges.txt");


    for (i = 0; i < num_procs; i++)
    {

        int rows_i = base_rows + (i < extra_rows ? 1 : 0);
        int start_row = (i * base_rows) + (i < extra_rows ? i : extra_rows);
        int end_row   = start_row + rows_i;            // exclusive
        if (rows_i == 0) { start_row = end_row = 0; }  // degenerate tiny N

        // 2) Logical elements this thread must produce
        size_t elems_i = (size_t)rows_i * (size_t)N;
        size_t bytes_i = elems_i * sizeof(int);

        // 3) mmap enough pages (at least one page) to store elems_i
        size_t pages_i = (bytes_i + page_sz - 1) / page_sz;
        if (pages_i == 0) pages_i = 1;
        size_t map_bytes = pages_i * page_sz;

        // build args
        arg[i] = malloc(sizeof(mm_data_t));
        arg[i]->tid          = i;
        arg[i]->matrix_A     = data->matrix_A;
        arg[i]->matrix_B     = data->matrix_B;
        arg[i]->matrix_len   = N;
        arg[i]->start_row    = start_row;
        arg[i]->end_row      = end_row;       // exclusive
        arg[i]->num_pages    = pages_i;
        
        // Map private region for this thread
        arg[i]->output_start = mmap(NULL, map_bytes,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                                    -1, 0);
        if (arg[i]->output_start == MAP_FAILED) { perror("mmap"); exit(1); }
        arg[i]->output_end   = (int *)((uintptr_t)arg[i]->output_start + map_bytes);

        elem_cursor += elems_i;


        if ( f ){
            fprintf(f, "base=%p page_size=%zu num_pages=%d\n", arg[i]->output_start, page_size, map_bytes/page_size);
            fflush(f);
            printf("Thread %d, base=%p page_size=%zu num_pages=%d\n", i, arg[i], page_size, 1);
        }
         fprintf(stderr,
        "[SETUP T%d] rows %d→%d (%zu elems), mmap %zu bytes (%zu pages) at %p–%p\n",
        i, start_row, end_row, elems_i, map_bytes, pages_i,
        arg[i]->output_start, arg[i]->output_end);
       
	    if(i) CHECK_ERROR(pthread_create(&pid[i], &attr, matrixmult_map, (void*)arg[i]) != 0);
        
    }   
    matrixmult_map((void *)arg[0]);


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
                volatile char *base = (volatile char *)arg[i]->output_start;
                size_t pages = arg[i]->num_pages;
                size_t page_sz = page_size;  // already set by dsm_init_barrier_pages()

                fprintf(stderr, "[APP] Read-touching %zu pages for T%d (%p–%p)\n",
                        pages, i, arg[i]->output_start, arg[i]->output_end);

                for (size_t pg = 0; pg < pages; pg++) {
                    volatile char *addr = base + pg * page_sz;
                    volatile unsigned char tmp = *addr;  // read to trigger MISSING fault if needed
                    (void)tmp;  // suppress unused-var warning
                    if (pg < 4 || pg == pages - 1)  // throttle prints for huge regions
                        fprintf(stderr, "   [T%d] read page %zu @ %p\n", i, pg, addr);
                }
            }
            fprintf(stderr, "[APP] Completed read-touch of all thread output pages\n");
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
        for (i = 0; i < num_procs; i++) {
            pthread_join(pid[i] , NULL);   
        }
    }

    
    Global->finishtime = now_us();


    char outname[512];
    char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/matrix_multiply";
    snprintf(outname, sizeof(outname), "%s/%d_check.txt", dir, data->matrix_len);

    /* Open the reference file */
    FILE *inf = fopen(outname, "r");
    if (!inf) {
        perror("fopen read");
        exit(1);
    }
    f = fopen("/tmp/dsm_exec_time_sec", "w");

    printf("\n[MAIN] Reassembling full result (and checking):\n");

    int total_expected = data->matrix_len * data->matrix_len;
    int idx = 0;
    int ref_val;

   for (int i = 0; i < num_procs; i++) {
    int *p = arg[i]->output_start;
    int start_row = arg[i]->start_row;
    int end_row   = arg[i]->end_row;
    int N         = data->matrix_len;
    size_t elems  = (size_t)(end_row - start_row) * (size_t)N;

    for (size_t e = 0; e < elems && idx < total_expected; e++, idx++) {
        int dsm_val = p[e];

        if (fscanf(inf, "%d", &ref_val) != 1) {
            fprintf(stderr, "[WARN] reference file ended early at idx=%zu\n", idx);
            break;
        }

        if (dsm_val != ref_val) {
            // compute row/col relative to global matrix
            size_t local_row = e / N;
            size_t local_col = e % N;
            size_t global_row = start_row + local_row;
            size_t global_col = local_col;

            // page analysis
            uintptr_t base_addr = (uintptr_t)p;
            uintptr_t elem_addr = base_addr + e * sizeof(int);
            size_t offset_bytes = elem_addr - base_addr;
            size_t page_idx = offset_bytes / page_size;
            size_t in_page_off = offset_bytes % page_size;

            printf("\n[APP] ❌ mismatch in verification!\n");
            printf("  Thread:       %d\n", i);
            printf("  Global idx:   %zu (row=%zu, col=%zu)\n", idx, global_row, global_col);
            printf("  DSM value:    %d\n", dsm_val);
            printf("  Ref value:    %d\n", ref_val);
            printf("  Page index:   %zu (offset %zu bytes in page)\n", page_idx, in_page_off);
            printf("  Elem address: %p (base=%p)\n",
                   (void*)elem_addr, (void*)base_addr);
            printf("  Thread rows:  %d→%d (elems=%zu)\n\n",
                   start_row, end_row, elems);
            
                   if (f) { fprintf(f, "%.6f\n", -1); fclose(f); }
            fflush(stdout);
             exit(-1); // uncomment if you want to stop immediately
        }

        if (print && dsm_val == ref_val)
            printf("%d ", dsm_val);

        if (print && ((idx + 1) % N == 0))
            printf("\n");
    }
}

    
    printf("[APP] Total runtime: %.3f seconds\n", (Global->finishtime - Global->starttime) / 1e6);
    printf("[APP] ✅ MAtrix verification successful — all values match.\n");
   
    
    if (f) { printf("[APP] Printing into file:%s\n", outname); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
    else printf("Error open file %s\n", outname);


    fclose(inf);
    dprintf("MatrixMult_pthreads: MapReduce Completed\n");

    
    if (f) fclose(f);
    free(pid);
}

/** matrixmul_map()
 * Function that computes the products for each of the portions assigned to the thread
 */
void *matrixmult_map(void *args_in)
{
    mm_data_t *data = (mm_data_t *)args_in;

    if (!data || !data->matrix_A || !data->matrix_B ||
        !data->output_start || !data->output_end) {
        fprintf(stderr, "[num_procs%d] invalid args!\n", data ? data->tid : -1);
        return NULL;
    }

    int tid = data->tid;
    int idx0, idx1;
    volatile unsigned char *q0, *q1;
    const int N = data->matrix_len;
    int *A = data->matrix_A;
    int *B = data->matrix_B;
    int *local_out = data->output_start;

    // Compute how many elements fit here
    size_t total_elems = data->output_end - data->output_start;
    size_t rows_to_compute = data->end_row - data->start_row;
    size_t expected_elems = (size_t)rows_to_compute * (size_t)N;

    // Clamp to avoid overflow if rounding added padding
    if (expected_elems > total_elems)
        expected_elems = total_elems;

    fprintf(stderr,
        "[num_procs%d] Computing real matrix mult for rows %d→%d (%zu elems) into %p–%p\n",
        data->tid, data->start_row, data->end_row,
        expected_elems, data->output_start, data->output_end);

    size_t out_idx = 0;

   
   #if 1
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


    // --- Standard matrix multiplication restricted to this thread's rows ---
    for (int r = data->start_row; r < data->end_row; r++) {
        //printf("[T%d] Starting row %d (global row %d)\n", tid, r - data->start_row, r);
        for (int c = 0; c < N; c++) {
            int sum = 0;
            //printf("[T%d]   Computing cell (%d,%d): ", tid, r, c);
            for (int k = 0; k < N; k++) {
                int a_val = A[r * N + k];
                int b_val = B[k * N + c];

                int prod  = a_val * b_val;
                sum += prod;
                //printf("%d*%d=%d ", a_val, b_val, prod);
            }
            //printf("→ sum=%d\n", sum);

            // write into thread’s local mmap buffer
            local_out[out_idx++] = sum;

            // safety clamp
            if (out_idx >= total_elems) break;
        }
        //printf("[T%d] Finished row %d (out_idx=%zu)\n", tid, r, out_idx);
        if (out_idx >= total_elems) break;
    }
    //printf("[T%d] Finished computation: total_elems=%zu, out_idx=%zu\n",   tid, total_elems, out_idx);


    if(dsm_active && tid ){
        splash_barrier(Global, local_threads, tid); //sync LOCAL threads
        if (barrier_region && tid == auth_thread ) {
            // Touch first page for this barrier
            idx0 = current_barrier_index;
            q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
            q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

            fprintf(stderr, "[APP] auth_thread %d read barrier page %p (index=%d)\n",
                    auth_thread, (void*)q0, idx0);

            // Advance index
            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

            
            // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] auth_thread %d second read barrier page %p (index=%d)\n",
                   auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }
        splash_barrier(Global, local_threads, tid);
    }

    //free(args_in);
    #endif
    return (void *)0;
}

int main(int argc, char *argv[]) {
    
    int i,j, create_files;
    int fd_A, fd_B, fd_out,file_size;
    char * fdata_A, *fdata_B;
    int matrix_len;
    struct stat finfo_A, finfo_B;
    char * fname_A, *fname_B,*fname_out;
    int *matrix_A_ptr, *matrix_B_ptr;

    struct timeval starttime,endtime;
    
    srand( (unsigned)time( NULL ) );
    // Make sure a filename is specified
    if (argv[1] == NULL)
    {
        printf("USAGE: %s [side of matrix] [print] [bool create files]\n", argv[0]);
        exit(1);
    }
    
    //char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/matrix_multiply";
    fname_A = "matrix_file_A.txt";
    fname_B = "matrix_file_B.txt";
    fname_out = "matrix_file_out_pthreads.txt";
    CHECK_ERROR ( (matrix_len = atoi(argv[1])) < 0);
    file_size = ((matrix_len*matrix_len))*sizeof(int);

    fprintf(stderr, "***** file size is %d\n", file_size);

    print = (argc > 2);
    create_files = (argc > 3);


    printf("MatrixMult_pthreads: Side of the matrix is %d\n", matrix_len);
    printf("MatrixMult_pthreads: Running...\n");

    CHECK_ERROR((fd_out = open(fname_out,O_CREAT | O_RDWR,S_IRWXU)) < 0);

	 /* If the matrix files do not exist, create them */
    if(create_files)
    {
	    dprintf("Creating files\n");

	    int value = 0;
	    CHECK_ERROR((fd_A = open(fname_A,O_CREAT | O_RDWR,S_IRWXU)) < 0);
	    CHECK_ERROR((fd_B = open(fname_B,O_CREAT | O_RDWR,S_IRWXU)) < 0);
	    
	    for(i=0;i<matrix_len;i++)
	    {
		    for(j=0;j<matrix_len;j++)
		    {
			    value = (rand())%11;
			    write(fd_A,&value,sizeof(int));
			    dprintf("%d  ",value);
		    }
		    dprintf("\n");
	    }
	    dprintf("\n");

	    for(i=0;i<matrix_len;i++)
	    {
		    for(j=0;j<matrix_len;j++)
		    {
			    value = (rand())%11;
			    write(fd_B,&value,sizeof(int));
			    dprintf("%d  ",value);
		    }
		    dprintf("\n");
	    }

	    CHECK_ERROR(close(fd_A) < 0);
	    CHECK_ERROR(close(fd_B) < 0);
    }

    // Read in the file
    CHECK_ERROR((fd_A = open(fname_A,O_RDONLY)) < 0);
    // Get the file info (for file length)
    CHECK_ERROR(fstat(fd_A, &finfo_A) < 0);

    // Memory map the file
    CHECK_ERROR((fdata_A= mmap(0, file_size + 1,
        PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_A, 0)) == NULL);

    // Read in the file
    CHECK_ERROR((fd_B = open(fname_B,O_RDONLY)) < 0);
    // Get the file info (for file length)
    CHECK_ERROR(fstat(fd_B, &finfo_B) < 0);
    // Memory map the file
    CHECK_ERROR((fdata_B= mmap(0, file_size + 1,
        PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_B, 0)) == NULL);

    // Setup splitter args
    mm_data_t mm_data;
    mm_data.matrix_len = matrix_len;
    mm_data.matrix_A = NULL;
    mm_data.matrix_B = NULL;

    mm_data.output = (int*)malloc(matrix_len*matrix_len*sizeof(int));
    
    mm_data.matrix_A = matrix_A_ptr = ((int *)fdata_A);
    mm_data.matrix_B = matrix_B_ptr = ((int *)fdata_B);

    printf("MatrixMult_pthreads: Calling MapReduce Scheduler Matrix Multiplication\n");

	gettimeofday(&starttime,0);
    
    matrixmult_splitter(&mm_data);
    
    gettimeofday(&endtime,0);

    printf("MatrixMult_pthreads: Multiply Completed time = %ld\n", (endtime.tv_sec - starttime.tv_sec));

    free(mm_data.output);

    CHECK_ERROR(munmap(fdata_A, file_size + 1) < 0);
    CHECK_ERROR(close(fd_A) < 0);

    CHECK_ERROR(munmap(fdata_B, file_size + 1) < 0);
    CHECK_ERROR(close(fd_B) < 0);

    CHECK_ERROR(close(fd_out) < 0);

    return 0;
}
