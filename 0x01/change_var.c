#include<stdio.h>

int main()
{
  char buf[100];
  int change_me = 49;
  printf("I dare you to change the value %d\n", change_me);
  gets(buf);
  if (change_me == 50)
  {
	  printf("You changed me!!, here's have this gift\n");
	  system("/bin/bash");
  }
  else
  {
	  printf("You can't change me, ( •̀ᴗ•́ )و ̑̑\n");
  }
  return 0;
}



