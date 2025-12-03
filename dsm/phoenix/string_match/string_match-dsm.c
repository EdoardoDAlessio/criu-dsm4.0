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
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <crypt.h>
#include <pthread.h>
#include <sys/time.h>
#include <inttypes.h>

#include "map_reduce.h"
#include "stddefines.h"

#define DEFAULT_UNIT_SIZE 5
#define SALT_SIZE 2
#define MAX_REC_LEN 1024
#define OFFSET 5


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


typedef struct {
  int keys_file_len;
  int encrypted_file_len;
  long bytes_comp;
  char * keys_file;
  char * encrypt_file;
} str_data_t;

typedef struct {
  char * keys_file;
  char * encrypt_file;
  int TID;
} str_map_data_t;

 char *key1 = "Helloworld";
 char *key2 = "howareyou";
 char *key3 = "ferrari";
 char *key4 = "whotheman";

 char *key1_final;
 char *key2_final;
 char *key3_final;
 char *key4_final;


void string_match_splitter(void *data_in);
int getnextline(char* output, int max_len, char* file);
void *string_match_map(void *args);
void string_match_reduce(void *key_in, void **vals_in, int vals_len);
void compute_hashes(char* word, char* final_word);

/** getnextline()
 *  Function to get the next word
 */
int getnextline(char* output, int max_len, char* file)
{
	int i=0;
	while(i<max_len-1)
	{
		if( file[i] == '\0')
		{
			if(i==0)
				return -1;
			else
				return i;
		}
		if( file[i] == '\r')
			return (i+2);

		if( file[i] == '\n' )
			return (i+1);

		output[i] = file[i];
		i++;
	}
	file+=i;
	return i;
}

/** compute_hashes()
 *  Simple Cipher to generate a hash of the word 
 */
void compute_hashes(char* word, char* final_word)
{
	int i;

	for(i=0;i<strlen(word);i++) {
		final_word[i] = word[i]+OFFSET;
	}
	final_word[i] = '\0';
}

/** string_match_splitter()
 *  Splitter Function to assign portions of the file to each thread
 */
void string_match_splitter(void *data_in)
{
	key1_final = malloc(strlen(key1) + 1);
	key2_final = malloc(strlen(key2) + 1);
	key3_final = malloc(strlen(key3) + 1);
	key4_final = malloc(strlen(key4) + 1);

	compute_hashes(key1, key1_final);
	compute_hashes(key2, key2_final);
	compute_hashes(key3, key3_final);
	compute_hashes(key4, key4_final);

    pthread_attr_t attr;
    pthread_t * tid;
    int i, num_procs;


   
    // DSM init page for mypthread_barrier 
    Global = (struct GlobalMemory *) malloc(sizeof(struct GlobalMemory));
    const char *env = getenv("DSM");
    if (env) {
        printf("DSM detected, using DSM pthread_barrier\n");
        dsm_init_barrier_pages();
        dsm_active = 1;
        num_procs = atoi(env);  // threads count from DSM env
        printf("Num threads:%d, iterations:%d, size of thread arg:%d\n", num_procs, iterations);
    } else {
        CHECK_ERROR((num_procs = sysconf(_SC_NPROCESSORS_ONLN)) <= 0);
    }

    printf("THe number of processors is %d\n", num_procs);

    str_data_t * data = (str_data_t *)data_in; 

    /* Check whether the various terms exist */
    assert(data_in);

    tid = (pthread_t *)MALLOC(num_procs * sizeof(pthread_t));

    /* Thread must be scheduled systemwide */
    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

    int req_bytes = data->keys_file_len / num_procs;

    str_map_data_t *map_data = (str_map_data_t*)malloc(sizeof(str_map_data_t) 
                                                                                        * num_procs);
    map_args_t* out = (map_args_t*)malloc(sizeof(map_args_t) * num_procs);

    for(i=0; i<num_procs; i++)
    {
	    map_data[i].encrypt_file = data->encrypt_file;
	    map_data[i].keys_file = data->keys_file + data->bytes_comp;
	    map_data[i].TID = i;
	    	    
	    /* Assign the required number of bytes */	    
	    int available_bytes = data->keys_file_len - data->bytes_comp;
	    if(available_bytes < 0)
		    available_bytes = 0;

	    out[i].length = (req_bytes < available_bytes)? req_bytes:available_bytes;
	    out[i].data = &(map_data[i]);


	    char* final_ptr = map_data[i].keys_file + out[i].length;
	    int counter = data->bytes_comp + out[i].length;

		 /* make sure we end at a word */
	    while(counter <= data->keys_file_len && *final_ptr != '\n'
			 && *final_ptr != '\r' && *final_ptr != '\0')
	    {
		    counter++;
		    final_ptr++;
	    }
	    if(*final_ptr == '\r')
		    counter+=2;
	    else if(*final_ptr == '\n')
		    counter++;

	    out[i].length = counter - data->bytes_comp;
	    data->bytes_comp = counter;
	    if(i) CHECK_ERROR(pthread_create(&tid[i], &attr, string_match_map, (void*)(&(out[i]))) != 0);
    }
    string_match_map(&out[0]);


    pthread_attr_destroy(&attr);
    free(tid);
    free(key1_final);
    free(key2_final);
    free(key3_final);
    free(key4_final);
    free(out);
    free(map_data);
}

/** string_match_map()
 *  Map Function that checks the hash of each word to the given hashes
 */
 #if 0
void *string_match_map(void *args)
{
     assert(args);
    
    str_map_data_t* data_in = (str_map_data_t*)( ((map_args_t*)args)->data);
    

    if( dsm_active){
        check_halt_file(data_in->TID);

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
    



   
	int key_len, total_len = 0;
	char * key_file = data_in->keys_file;
	char * cur_word = malloc(MAX_REC_LEN);
	char * cur_word_final = malloc(MAX_REC_LEN);
	bzero(cur_word, MAX_REC_LEN);
	bzero(cur_word_final, MAX_REC_LEN);

	while( (total_len < ((map_args_t*)args)->length) && ((key_len = getnextline(cur_word, MAX_REC_LEN, key_file)) >= 0))
     {
		compute_hashes(cur_word, cur_word_final);

	    if(!strcmp(key1_final, cur_word_final))
		    printf("FOUND: WORD IS %s\n", cur_word);

	    if(!strcmp(key2_final, cur_word_final))
		    printf("FOUND: WORD IS %s\n", cur_word);

	    if(!strcmp(key3_final, cur_word_final))
		    printf("FOUND: WORD IS %s\n", cur_word);

	    if(!strcmp(key4_final, cur_word_final))
		    printf("FOUND: WORD IS %s\n", cur_word);

		key_file = key_file + key_len;
		bzero(cur_word,MAX_REC_LEN);
		bzero(cur_word_final, MAX_REC_LEN);
		total_len+=key_len;
    }
    free(cur_word);
    free(cur_word_final); 
    return (void *)0;
}
#else 
void *string_match_map(void *args)
{
    assert(args);
    
    str_map_data_t* data_in = (str_map_data_t*)( ((map_args_t*)args)->data);
    
    int idx0, idx1;
    volatile unsigned char *q0, *q1;
    
    if( dsm_active){
        check_halt_file(data_in->TID);

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


    char *initial_key_file = data_in->keys_file;
    int chunk_len = ((map_args_t*)args)->length;

    for (int it = 0; it < iterations; it++) {

        int key_len, total_len = 0;
        char *key_file = initial_key_file;

        char *cur_word = malloc(MAX_REC_LEN);
        char *cur_word_final = malloc(MAX_REC_LEN);
        bzero(cur_word, MAX_REC_LEN);
        bzero(cur_word_final, MAX_REC_LEN);

        while (total_len < chunk_len &&
               (key_len = getnextline(cur_word, MAX_REC_LEN, key_file)) >= 0)
        {
            compute_hashes(cur_word, cur_word_final);

            if (!strcmp(key1_final, cur_word_final))
                dprintf("FOUND: WORD IS %s\n", cur_word);
            if (!strcmp(key2_final, cur_word_final))
                dprintf("FOUND: WORD IS %s\n", cur_word);
            if (!strcmp(key3_final, cur_word_final))
                dprintf("FOUND: WORD IS %s\n", cur_word);
            if (!strcmp(key4_final, cur_word_final))
                dprintf("FOUND: WORD IS %s\n", cur_word);

            key_file += key_len;
            bzero(cur_word, MAX_REC_LEN);
            bzero(cur_word_final, MAX_REC_LEN);
            total_len += key_len;
        }

        free(cur_word);
        free(cur_word_final);
    }


    splash_barrier(Global, local_threads, 0); //sync LOCAL threads
    if (barrier_region && data_in->TID == auth_thread ) {
        // Touch first page for this barrier
        idx0 = current_barrier_index;
        q0 = (volatile unsigned char *)barrier_region + (size_t)idx0 * page_size;
        q0[0] = (unsigned char)(q0[0] ^ 1); // write to trigger WP fault

        fprintf(stderr, "[APP] main %d wrote to barrier page %p (index=%d)\n",
                auth_thread, (void*)q0, idx0);

        // Advance index
        current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;

    }


    return (void *)0;
}

#endif
int main(int argc, char *argv[]) {
    int fd_keys;
    char *fdata_keys;
    struct stat finfo_keys;
    char *fname_keys;

	 /* Option to provide the encrypted words in a file as opposed to source code */
    //fname_encrypt = "encrypt.txt";
    
    if (argv[1] == NULL)
    {
        printf("USAGE: %s <keys filename>\n", argv[0]);
        exit(1);
    }
    fname_keys = argv[1];
    if (argc > 2) iterations = atoi(argv[2]);
    printf("Running %d iterations...\n", iterations);

    struct timeval starttime,endtime;
    srand( (unsigned)time( NULL ) );

    /*// Read in the file
    CHECK_ERROR((fd_encrypt = open(fname_encrypt,O_RDONLY)) < 0);
    // Get the file info (for file length)
    CHECK_ERROR(fstat(fd_encrypt, &finfo_encrypt) < 0);
    // Memory map the file
    CHECK_ERROR((fdata_encrypt= mmap(0, finfo_encrypt.st_size + 1,
        PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_encrypt, 0)) == NULL);*/

    // Read in the file
    CHECK_ERROR((fd_keys = open(fname_keys,O_RDONLY)) < 0);
    // Get the file info (for file length)
    CHECK_ERROR(fstat(fd_keys, &finfo_keys) < 0);
    // Memory map the file
    CHECK_ERROR((fdata_keys= mmap(0, finfo_keys.st_size + 1,
        PROT_READ | PROT_WRITE, MAP_PRIVATE, fd_keys, 0)) == NULL);

    // Setup splitter args

	//dprintf("Encrypted Size is %ld\n",finfo_encrypt.st_size);
	dprintf("Keys Size is %" PRId64 "\n",finfo_keys.st_size);

    str_data_t str_data;

    str_data.keys_file_len = finfo_keys.st_size;
    str_data.encrypted_file_len = 0;
    str_data.bytes_comp = 0;
    str_data.keys_file  = ((char *)fdata_keys);
    str_data.encrypt_file  = NULL;
    //str_data.encrypted_file_len = finfo_encrypt.st_size;
    //str_data.encrypt_file  = ((char *)fdata_encrypt);     

    printf("String Match: Calling Serial String Match\n");

    gettimeofday(&starttime,0);
    string_match_splitter(&str_data);
    gettimeofday(&endtime,0);

    
    Global->finishtime = now_us();
    printf("[APP] Total runtime: %.3f seconds\n", (Global->finishtime - Global->starttime) / 1e6);
    printf("String Match: Completed %ld\n",(endtime.tv_sec - starttime.tv_sec));

    FILE* f = fopen("/tmp/dsm_exec_time_sec", "w");

    if (f) { printf("[APP] Printing into file:/tmp/dsm_exec_time_sec\n"); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
    else printf("Error open file /tmp/dsm_exec_time_sec\n");
   

    /*CHECK_ERROR(munmap(fdata_encrypt, finfo_encrypt.st_size + 1) < 0);
    CHECK_ERROR(close(fd_encrypt) < 0);*/

    //CHECK_ERROR(munmap(fdata_keys, finfo_keys.st_size + 1) < 0);
    CHECK_ERROR(close(fd_keys) < 0);

    return 0;
}
