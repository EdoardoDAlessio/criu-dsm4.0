
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define ROW 1000
#define COL 10000
// Function that performs Radix Sort
void radix_sort(int arr[], int n){

    // Step 1: Find the maxumum element
    int maximum = arr[0];

    for(int i=1;i<n;i++){
        if(maximum < arr[i])
            maximum = arr[i];
    }

    // Step 2: Count the number of digits of the maximum number
    int digits = 0;

    while(maximum > 0){
        digits++;
        maximum /= 10;
    }

    // Units/Tens/Hundreds - used to determine which digit
    int power = 1;

    // Step 3, 4, 5: Arrange the numbers on the basis of digits
    for(int i=0;i<digits;i++){

        // Holds the updated array
        int new_array[n];

        // Counting Sort Array - required for arranging digits [0-9]
        int count[10];

        // Initializing Count Array
        for(int j=0;j<10;j++)
            count[j] = 0;

        // Calculating frequency of digits
        for(int j=0;j<n;j++){

            // The digit under consideration in this iteration
            int num = (arr[j]/power) % 10;

            count[num]++;
        }

        // Cumulative frequency of count array
        for(int j=1;j<10;j++){
            count[j] += count[j-1];
        }

        // Designating new positions in the updated array
        for(int j=n-1;j>=0;j--){

            // The digit under consideration in this iteration
            int num = (arr[j]/power) % 10;

            new_array[count[num]-1] = arr[j];
            count[num]--;
        }

        // Updating the original array using New Array
        for(int j=0;j<n;j++)
            arr[j] = new_array[j];

        // Updating the digit to be considered next iteration
        power *= 10;
    }

    // Printing the sorted array
/*    for(int j=0;j<n;j++)
        printf("%d ", arr[j]);
    printf("\n");*/
}
void fill_random(int array[ROW][COL], int max)
{
  for (int i = 0; i < ROW; i++)
  {
    for (int j = 0; j < COL; j++)
    {
      array[i][j] = (rand() % max) + 1;
    }
  }
}

void scalar_mul(int arr[]){
{
  for (int i = 0; i < COL; i++)
  {
      arr[i] = arr[i] * 2 ;
	  //printf("%d ", arr[i]);
    }
	//printf("\n");
  }
}

// The main function
int radix(){

	srand( time(NULL) );
	int arr[ROW][COL];
    //int** arr = malloc ((ROW*COL)*sizeof(int));
	fill_random(arr, 1000);
	int arr_tmp[COL];

	 // print out the 2D array
	/*printf("Original 2-D array\n");
	for (int i = 0; i < ROW; i++){
		for (int j = 0; j < COL; j++){
			printf("%3d ", arr[i][j]);
		}
    printf("\n");
	}
	printf("\n");
	printf("Sorted 2-D array\n");*/
	for(int j = 0; j < ROW; j++){
		for(int i = 0; i < COL; i++){
			// ROW of the array
			arr_tmp[i] = arr[j][i];
			//printf("%d  ",arr_tmp[i]);
		}
		//printf("\n");
		int n = sizeof(arr_tmp)/sizeof(n);
 		// Function call for the Radix Sort Algorithm
		radix_sort(arr_tmp, n);

		//copy the temp array to the original 2-D array
		for(int i = 0; i < COL; i++){
			// ROW of the array
			arr[j][i] = arr_tmp[i];
			//printf("%d  ",arr_tmp[i]);
		}

	}/*
	printf("\n");
	printf("Multiplied 2-D array\n");*/
	for(int j = 0; j < ROW; j++){
		for(int i = 0; i < COL; i++){
			// ROW of the array
			arr_tmp[i] = arr[j][i];
			//printf("%d  ",arr_tmp[i]);
	}
		scalar_mul(arr_tmp);
	}
    //free(arr);
    return 0;
}

int radix2(){
	
	int a[1000];
	for (int i=0;i<1000;i++)
		for (int j=0;j<1000;j++)
			for (int k=0;k<200;k++)
				a[i] *= a[i]+9;	

	return 0;
}

