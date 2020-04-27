// struct
// the example is taken from divine paper

#include <stdio.h>

struct P
{
  int a;
  int b;
};

int main()
{
  struct P p, *pp;
  pp = &p;
  pp->a = 4;
  pp->b = 8;
  printf("%d\n", pp->a);
  printf("%d\n", pp->b);
  return 0;
}
