#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//gcc -no-pie -o monster monster.c


int16_t monster_health = 32000;

void menu()
{
	puts("=========================");
	puts("\tMonster");
	puts("=========================");
	puts("1. Beat the monster");
	puts("2. Have a break");
	puts("3. Surrender");
	puts("");
	printf("Your choice> ");
}

void beat_monster()
{
	if (monster_health < 100)
		return;
	puts("How dare you?");
	monster_health--;
	printf("Monster health: %hd\n",monster_health);
}

void have_a_break()
{
	puts("Thank you");
	monster_health++;
	printf("Monster health: %hd\n",monster_health);
}

void check_monster_health()
{
	if (monster_health <= 0)
		system("/bin/cat flag.txt");
}

int main()
{
	setvbuf(stdout,0,2,0);

	while(1)
	{
		menu();
		int choice = 1;
		if (scanf("%d", &choice) != 1)
			return 1;
		switch (choice)
		{
			case 1:
				beat_monster();		
				break;
			case 2:
				have_a_break();
				break;
			case 3:
				exit(0);
				break;
			default:
				puts("Invalid choice");
		}
		check_monster_health();
	}
	return 0;
}
