    /* PCA with DSM-ready threading: lock-free work split, DSM env, barriers */
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdarg.h>
    #include <string.h>
    #include <unistd.h>
    #include <assert.h>
    #include <math.h>
    #include <errno.h>
    #include <sys/mman.h>
    #include <sys/time.h>
    #include <pthread.h>

    /* ---------- Tiny helpers (Phoenix-style) ---------- */
    #define CHECK_ERROR(stmt) do { if ((stmt)) { \
        fprintf(stderr,"Error @ %s:%d: %s\n", __FILE__, __LINE__, strerror(errno)); \
        exit(1); } } while (0)

    #ifndef PAGE_SIZE
    #define PAGE_SIZE 4096
    #endif

    /* ---------- Problem defaults ---------- */
    #define DEF_GRID_SIZE 100
    #define DEF_NUM_ROWS  10
    #define DEF_NUM_COLS  10

    /* ---------- Globals (problem) ---------- */
    static int num_rows, num_cols, grid_size;
    static int **matrix, **cov;
    static int *mean;
    int log_enable = 0;

    typedef struct{
        int tid;
        int start;
        int end;
        int mean_pages;
        int cov_i_j_pages;
        int cov_j_pages;
        int* local_mean;
        int **local_cov_i_j;
        int * local_cov_i_j_data;
    }thread_arg_t;

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
        if(log_enable) printf("Thread %d: Waiting for haltcode file /tmp/haltcode to continue...\n", tid);
        fflush(stdout);
        while(access("/tmp/haltcode", F_OK) != 0) {
            //spin wait for haltcode file
        }
        if(log_enable) printf("Thread %d: Haltcode file detected, continuing execution\n", tid);
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



    /* ---------- Input/Output helpers ---------- */
    static void parse_args(int argc, char **argv){
        int c; num_rows = DEF_NUM_ROWS; num_cols = DEF_NUM_COLS; grid_size = DEF_GRID_SIZE;
        while ((c = getopt(argc, argv, "r:c:s:l:p:")) != -1){
            switch(c){
                case 'r': num_rows = atoi(optarg); break;
                case 'c': num_cols = atoi(optarg); break;
                case 's': grid_size = atoi(optarg); break;
                case 'l': log_enable = 1; break;
                case 'p': total_threads = atoi(optarg); break;
                default:
                    printf("Usage: %s -r <rows> -c <cols> -s <maxval>\n", argv[0]);
                    exit(1);
            }
        }
        if (num_rows<=0 || num_cols<=0 || grid_size<=0){
            fprintf(stderr,"All values must be > 0\n"); exit(1);
        }
        printf("rows=%d cols=%d max=%d\n", num_rows, num_cols, grid_size);
    }

    static void generate_points(int **pts, int rows, int cols){
        for (int i=0;i<rows;i++)
            for (int j=0;j<cols;j++)
                pts[i][j] = rand() % grid_size;
    }

    static void dump_points(int **vals, int rows, int cols){
        for (int i=0;i<rows;i++){
            for (int j=0;j<cols;j++) printf("%5d ", vals[i][j]);
            printf("\n");
        }
    }

    void dump_points_check(int **vals, int rows, int cols)
    {
    int i, j;
        (void) i;
        (void) j;
        char *dir = "/users/EdoDale/phoenix/phoenix-2.0/tests/pca";
        char outname[512];
        snprintf(outname, sizeof(outname), "%s/pca_r%d_c%d_s%d_check.txt", dir, num_rows, num_cols, grid_size);
        FILE *inf = fopen(outname, "r");
        if (!inf) {
            printf("Filename:%s\n", outname);
            perror("fopen check");
            exit(1);
        }

        /* optional: allocate buffer to read back into */
        int read_val;
        printf("[CHECK] Reading results from %s\n", outname);
        int mismatch = 0;
        for (int i=0;i<rows;i++){
            for (int j=0;j<cols;j++){
                if (fscanf(inf, "%d", &read_val) != 1) {
                    fprintf(stderr, "Error reading value at row %d col %d\n", i, j);
                    exit(1);
                }
                if(log_enable) printf("%5d ", vals[i][j]);

                if (read_val != vals[i][j]){
                    
                    mismatch++;
                    printf("  <-- mismatch at %d:%d(expected %d)", i, j, read_val);
                    exit(-1);
                }
                    

            } 
            if(log_enable) printf("\n");
        }

        FILE *f = fopen("/tmp/dsm_exec_time_sec", "w");

        if (mismatch == 0){
            printf("[APP] ✅ PCA verification successful — all values match.\n");
            if (f) { printf("[APP] Printing into file\n"); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
            else printf("Error open file \n");
        }
        else{
            printf("[APP] ❌ %d mismatches found in PCA verification.\n", mismatch);
            if (f) { fprintf(f, "%.6f\n", -1); fclose(f); }
        }
            

        fclose(inf);
        
    }



    /* ---------- Mean stage ---------- */
    static void* calc_mean_thread(void* argp) {
        thread_arg_t* a = (thread_arg_t*)argp;
        for (int i = a->start; i < a->end; i++) {
            long sum = 0;
            for (int j = 0; j < num_cols; j++)
                sum += matrix[i][j];
            a->local_mean[i - a->start] = sum / num_cols;
        }
        return NULL;
    }



    /* ---------- Covariance stage (lock-free; disjoint i-blocks) ---------- */



    static void* calc_cov_thread(void *argp) {
        thread_arg_t *a = (thread_arg_t*)argp;
        int tid = a->tid;

        /**/char outname[512];
        snprintf(outname, sizeof(outname), "cov_r%d_c%d_s%d_check.txt", num_rows, num_cols, grid_size);
        FILE *inf = fopen(outname, "r");
        if (!inf) {
            printf("Filename:%s\n", outname);
            perror("fopen check");
            //exit(1);
        }
        inf = NULL;

        //* optional: allocate buffer to read back into */
        int i1, j1, i2, covij, covj;

        /* Each thread owns a disjoint block of rows [start, end).
        mean[] is now the node-global array already populated.  */
        for (int i = a->start; i < a->end; i++) {
            while (inf && fscanf(inf, "cov[%d][%d]:%d cov[%d]:%d\n", &i1, &j1, &covij, &i2, &covj) == 5) {
                if( i1 == i ) break;
            } 

            for (int j = i; j < num_rows; j++) {   
                long sum = 0;
                for (int k = 0; k < num_cols; k++) {
                    long di = (long)matrix[i][k] - (long)mean[i];
                    long dj = (long)matrix[j][k] - (long)mean[j];
                    sum += di * dj;
                }
                int val = (int)(sum / (num_cols - 1));

                /* store results in thread-local DSM-mapped pages */
                a->local_cov_i_j[i - a->start][j] = val;
                
                if( inf ){
                    if (i1 != i || j1 != j || i2 != j) {
                        fprintf(stderr, "Index mismatch: expected cov[%d][%d] cov[%d], got cov[%d][%d] cov[%d]\n",
                                i, j, j, i1, j1, i2);
                        exit(1);
                    }

                    if (val != covij) {
                        fprintf(stderr, "Value mismatch at [%d][%d]: got %d, expected %d\n",
                                i, j, val, covij);
                        exit(-1);
                    }
                }
            

                if(log_enable) printf("cov[%d][%d]:%d cov[%d]:%d\n", i, j, val, j, val);/**/
                cov[i][j] = val;
                cov[j][i] = val;

            }
        }

        return NULL;
    }

    int total_threads;
    thread_arg_t *arg;
    #define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

    void* dsm_wrapper(void* arg_p);
    /* ---------- Main ---------- */
int main(int argc, char **argv){
        parse_args(argc, argv);

        /* Allocate matrix */
        matrix = (int**)malloc(sizeof(int*)*num_rows);
        for (int i=0;i<num_rows;i++) matrix[i] = (int*)malloc(sizeof(int)*num_cols);
        generate_points(matrix, num_rows, num_cols);

        mean = (int*)malloc(sizeof(int)*num_rows);
        cov  = (int**)malloc(sizeof(int*)*num_rows);
        for (int i=0;i<num_rows;i++) cov[i] = (int*)calloc(num_rows, sizeof(int) );

        
        // Print the points
    if(log_enable) dump_points(matrix, num_rows, num_cols);

        /* Decide threads: getenv("DSM") overrides CPUs. */
        // DSM init page for mypthread_barrier 
        Global = (struct GlobalMemory *) malloc(sizeof(struct GlobalMemory));
        CHECK_ERROR(!Global);
        memset(Global, 0, sizeof(*Global));

        CHECK_ERROR(pthread_mutex_init(&(Global->start).mutex, NULL));
        CHECK_ERROR(pthread_cond_init(&(Global->start).cv, NULL));
        (Global->start).counter = 0;
        (Global->start).cycle   = 0;

        const char *env = getenv("DSM");
        if (env) {
            printf("DSM detected, using DSM pthread_barrier\n");
            dsm_init_barrier_pages();
            dsm_active = 1;
            //total_threads = atoi(env);  // threads count from DSM env
            printf("Num threads:%d, log:%d\n", total_threads, log_enable);
        } else {
        total_threads = sysconf(_SC_NPROCESSORS_ONLN);
        }
        /*DSM CREATE THreads*/
        pthread_t *tids = (pthread_t*)malloc(sizeof(pthread_t)*total_threads);
        pthread_attr_t attr; pthread_attr_init(&attr);
        pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

        int base = num_rows / total_threads;
        int extra = num_rows % total_threads;
        int row = 0;

        arg = (thread_arg_t *)malloc(sizeof(thread_arg_t )* total_threads);

        FILE *f = fopen("/tmp/ranges.txt", "w");
        for (int i = 0; i < total_threads; i++) {
            int take = base + (i < extra ? 1 : 0);

            arg[i].tid   = i;
            arg[i].start = row;
            arg[i].end   = row + take;
            row += take;

            int rows_for_thread = take;
            size_t mean_bytes = rows_for_thread * sizeof(int);
            size_t cov_j_bytes   = num_cols * sizeof(int);

            size_t mean_pages    = PAGE_ALIGN(mean_bytes);
            size_t cov_j_pages   = PAGE_ALIGN(cov_j_bytes);

            arg[i].mean_pages = mean_pages / PAGE_SIZE;
            arg[i].cov_j_pages = cov_j_pages / PAGE_SIZE;

            arg[i].local_mean = mmap(NULL, mean_pages,
                                    PROT_READ|PROT_WRITE,
                                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);

            #if 0

            size_t cov_i_j_bytes = rows_for_thread * num_rows * sizeof(int);
            size_t cov_i_j_pages = PAGE_ALIGN(cov_i_j_bytes);
            arg[i].local_cov_i_j = mmap(NULL, cov_i_j_pages,
                                        PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
        
            #else

            /* page-sized contiguous region for all data */
            size_t cov_i_j_bytes = rows_for_thread * num_rows * sizeof(int);
            size_t cov_i_j_pages = PAGE_ALIGN(cov_i_j_bytes);


            arg[i].cov_i_j_pages = cov_i_j_pages / PAGE_SIZE;

            /* allocate pointer array (local) */
            int **cov_rows = malloc(rows_for_thread * sizeof(int *));

            /* allocate page-aligned data region (shared candidate) */
            int *cov_data = mmap(NULL, cov_i_j_pages,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                                -1, 0);
            if (cov_data == MAP_FAILED) {
                perror("mmap local_cov_i_j");
                exit(1);
            }

            /* map 2D pointers into contiguous mmap block */
            for (int r = 0; r < rows_for_thread; r++) {
                cov_rows[r] = cov_data + r * num_rows;
            }

            /* store in struct */
            arg[i].local_cov_i_j = cov_rows;       /* 2D pointer view */
            arg[i].local_cov_i_j_data = cov_data;  /* real contiguous mmap base */
            arg[i].cov_i_j_pages = cov_i_j_pages / PAGE_SIZE;

            #endif


            if ( f ){
                fprintf(f, "base=%p page_size=%zu num_pages=%d\n", arg[i].local_mean, PAGE_SIZE, arg[i].mean_pages);
                fprintf(f, "base=%p page_size=%zu num_pages=%d\n", arg[i].local_cov_i_j_data, PAGE_SIZE, arg[i].cov_i_j_pages);
                fflush(f);
            }

            if (i) CHECK_ERROR(pthread_create(&tids[i], &attr, dsm_wrapper, &arg[i]) != 0);
            
        }
        dsm_wrapper(&arg[0]);

      

        if (dsm_active){
            Global->finishtime = now_us();
            printf("[APP] Total runtime: %.3f s\n", (Global->finishtime - Global->starttime)/1e6);
            f = fopen("/tmp/dsm_exec_time_sec", "w");
            if (f) { printf("[APP] Printing into file:/tmp/dsm_exec_time_sec\n"); fprintf(f, "%.6f\n", (Global->finishtime - Global->starttime) / 1e6); fclose(f); }
            else printf("Error open file /tmp/dsm_exec_time_sec\n");
        }
        if(log_enable) dump_points(cov, num_rows, num_rows);
        /* Print covariance (optional; comment out for large sizes) */
        dump_points_check(cov, num_rows, num_rows);
        /*
        printf("\n[WORKLOAD PER THREAD]\n");
        for (int i = 0; i < total_threads; i++) {
            thread_arg_t *a = &arg[i];

            int R = num_rows;
            int s = a->start;
            int e = a->end;
            int N = e - s;

            long long W = (long long)N * (2LL * R - (s + e - 1)) / 2LL;

            printf("Thread %d: rows [%d..%d) → %lld covariance pairs\n",
                a->tid, s, e, W);
        }
*/
    

        for (int i=0;i<num_rows;i++){ free(cov[i]); free(matrix[i]); }
        free(cov); free(matrix); free(mean);
        return 0;
    }

    void* dsm_wrapper(void* arg_p) {
        thread_arg_t* a = (thread_arg_t*)arg_p;
        int tid = a->tid;
        printf("[T%d] start=%d end=%d mean=%p, covij=%p, covijdata=%p\n",
            a->tid, a->start, a->end, a->local_mean, a->local_cov_i_j, a->local_cov_i_j_data);

        /* DSM init for first thread after restore */
        if (dsm_active) {
            check_halt_file(tid);
            pthread_mutex_lock(&once_lock);
            if (!done) {
                Global->starttime = now_us();
                done = 1;
                
                
                // Print the points
                if(log_enable) dump_points(matrix, num_rows, num_cols);

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

    
        

        calc_mean_thread(a);


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

        
            /* phase 3: compone the means */
            printf("[AUTH] %d Rebuilding global mean by touching each thread's local_mean pages...\n", auth_thread);

            for (int t = 0; t < total_threads; t++) {
                thread_arg_t ta = arg[t];
                volatile char *base = (volatile char*)ta.local_mean;   // define base here
                for (int pg = 0; pg < ta.mean_pages; pg++) {
                    volatile char *addr = base + (size_t)pg * PAGE_SIZE;
                    volatile char tmp = *addr;   // read-only touch
                    (void)tmp;
                    if(log_enable) fprintf(stderr, "[AUTH] touched mean page %d of thread %d (%p)\n",
                            pg, t, (void*)addr);
                }
            }

            /* Optional merge into global mean[] (if needed) */
            if (tid == auth_thread) {
                printf("[AUTH] Rebuilding global mean from local_mean arrays...\n");
                for (int t = 0; t < total_threads; t++) {
                    thread_arg_t ta = arg[t];
                    for (int r = 0; r < ta.end - ta.start; r++) {
                        int global_index = ta.start + r;
                        mean[global_index] = ta.local_mean[r];
                    }
                }

                printf("[AUTH] Mean recomposition done.\n");
            }


            //printf("[AUTH] Global mean recomposed successfully.\n");
            
            // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] auth_thread %d second barrier page %p (index=%d)\n",
                auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }
        splash_barrier(Global, local_threads, tid);

        if(log_enable) 
            {
                
            printf("\n[DSM PCA] Mean values after recomposition:\n");
            for (int i = 0; i < num_rows; i++) {
                    printf("%5d ", mean[i]);
                }
            printf("\n\n");
        }
        calc_cov_thread(a);
        //printf("Post calc cov thread%d\n", tid);

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

        
            /* phase 3: merge results on this node (auth thread only) */
            if (tid == 0) {
                for (int t = 0; t < total_threads; t++) {   // <--- fix here
                    thread_arg_t ta = arg[t];
                    //printf("PAGES:%d\n", ta.cov_i_j_pages);
                    volatile char *base = (volatile char*)ta.local_cov_i_j_data;
                    for (int pg = 0; pg < ta.cov_i_j_pages; pg++) {
                        //fprintf(stderr, "[TOUCH-DBG] thread %d touching cov_i_j pages=%d base=%p\n", t, ta.cov_i_j_pages, ta.local_cov_i_j_data);
                        //fflush(stderr);

                        volatile char *addr = base + (size_t)pg * PAGE_SIZE;
                        volatile char tmp = *addr;
                        (void)tmp;
                        //fprintf(stderr, "[AUTH] read cov_i_j page %d of thread %d (%p)\n", pg, t, (void*)addr);
                    }
                }

                for (int t = 0; t < total_threads; t++) {
                    thread_arg_t *ta = &arg[t];
                    for (int i = ta->start; i < ta->end; i++) {
                        for (int j = i; j < num_rows; j++) {
                            int val = ta->local_cov_i_j[i - ta->start][j];
                            cov[i][j] = val;
                            cov[j][i] = val;
                        }
                    }
                }
            }

            // Touchsecond, different page this barrier. WHY? So that nobody changed the prefaulted pages
            idx1 = current_barrier_index;
            q1 = (volatile unsigned char *)barrier_region + (size_t)idx1 * page_size;
            q1[0] = (unsigned char)(q1[0] ^ 1);

            fprintf(stderr, "[APP] auth_thread %d second barrier page %p (index=%d)\n",
                auth_thread, (void*)q1, idx1);

            current_barrier_index = (current_barrier_index + 1) % NUM_BARRIER_PAGES;
        }

        //printf("TID%d\n", tid);
        splash_barrier(Global, local_threads, tid);



        return NULL;
    }


    