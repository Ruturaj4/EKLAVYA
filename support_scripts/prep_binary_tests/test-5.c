#include <stdio.h>

struct P
{
  int a;
  int b;
};

struct Q
{
  int a;
  float b;
};

int main()
{
  struct P p, *pp;
  struct Q q;
  pp = &p;
  pp->a = 4;
  pp->b = 8;
  printf("%d\n", pp->a);
  printf("%d\n", pp->b);
  return 0;
}
