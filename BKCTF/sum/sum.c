#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{
	setvbuf(stdout,0,2,0);

	int64_t sum = 0;
	uint16_t num = 0;
	int64_t* root;
	puts("How many numbers do you want to sum up?");
	printf("> ");

	scanf("%hd%*c", &num);
	uint16_t size = num*sizeof(int64_t) + 0x10;
	if (size < num)
	{
		puts("No more integer overflow!!!");
		exit(1);
	}

	int64_t* array = (int64_t*) malloc(size);
	if (!array)
		exit(1);

	root = (uint16_t*) ((void*) array + size - 0x10);
	*root = 0;

	for (uint16_t i = 0; i < num; i++)
	{
		printf("Enter number %hd: ", i + 1);
		scanf("%lld", &array[i]);
		sum += array[i];
	}

	printf("Here is your sum: %lld\n", sum);
	if (*root != 0)
		system("/bin/cat flag.txt");
	
	// no free no problem
	return 0;
}
