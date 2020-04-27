// struct
#include <stdio.h>
#include <stdlib.h>
struct P
{
  int a;
  int b;
};

int main()
{
  struct P *p = (struct P*) malloc(sizeof(struct P));
  p->a = 4;
  p->b = 8;
  printf("%d\n", p->a);
  printf("%d\n", p->b);
  return 0;
}
