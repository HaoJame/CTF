#include <stdio.h>

void win()
{
  system("/bin/cat flag.txt");
}

int main()
{
  char buf[20];
  printf("Tell me your name: ");
  gets(buf);
  return 0;
}

