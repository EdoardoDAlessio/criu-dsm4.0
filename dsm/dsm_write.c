#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#define NUM_THREADS 4

#define ARR_SIZE 10000

#define MW 1 

int printTime(void);
int radix2();

int shared_array[ARR_SIZE];
int sum=0;
int cur_index=0;
pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;

int check_file(){

	if (access("/tmp/haltcode", F_OK) == 0) {
		return 1;
	} else {
		return 0;
	}
		   
}


int multi_read(int tid,int count){

	// read the share page value;
	if(shared_array[count] == -99) 
		return -1;
	if(count%10 == 0)
		printf("Thread[%d] readvalue count=%d\n", tid,shared_array[count]);
    	if(count%50 ==0)
	    	printTime();

    	radix2(); radix2(); radix2();
	return 0; 
}

void dummy_read(int tid,int count)
{
	if(check_file()){
		printf("press enter\n");
		getchar();
	}

	if(count%10 == 0)
		printf("Thread[%d] readvalue i=%d local=%d\n", tid,cur_index,count);
    	if(cur_index%50 ==0)
	    	printTime();

    	radix2(); radix2(); radix2();
	return; 
}

void dummy(int tid)
{
    int index;
    if(check_file()){
	    printf("press enter\n");
	    getchar();
    }
    radix2(); radix2(); radix2();
    pthread_mutex_lock(&mutex);
    index = cur_index++;
    sum += shared_array[index];
    printf("Thread[%d] processed %d sum=%d\n", tid,index,sum);
    if(cur_index >= ARR_SIZE){
    	printf("processed all values sum= %d\n",sum);
	printTime();
	exit(0);
    }   
    pthread_mutex_unlock(&mutex);
}

void *thread_func(void *argp)
{
    int thread_id;
    thread_id = *((int *)argp);
    int count = 0;
    while(1)
    {
#ifdef MR
	count++;
	multi_read(thread_id,count);
#endif
#ifdef MW
	dummy(thread_id);
#endif
	
#ifdef SWMR
	count++;
	if(thread_id == 0)
		dummy(thread_id);
	else
		dummy_read(thread_id,count);
#endif
    }
    return NULL;
}

int main(int argc, char *argv[])
{
	int THREADS = NUM_THREADS;
#ifdef MR
	printf("MR\n");
#endif
#ifdef MW
	printf("MW\n");
#endif
#ifdef SWMR
	printf("SWMR\n");
#endif
    if(argc >= 2)
	THREADS = atoi(argv[1]);

    printf("num_threads %d\n",THREADS);
    printTime();
    pthread_t threads[THREADS];
    int thread_ids[THREADS];
    int tid = 0;
    printTime();

    for(int i=0;i<ARR_SIZE;i++){
	    shared_array[i]=i+1;
    }

    for(int i = 1; i < THREADS; i++)
    {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, thread_func, (void *)&thread_ids[i]);
    }

    thread_func((void *)&tid); 

    return 0;
}
