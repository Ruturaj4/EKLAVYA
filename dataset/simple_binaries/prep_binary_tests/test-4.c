#include <stdio.h>

int fun(int a)
{
a = 5;
return a;
}

float foo(float a, int b)
{
a = 5.7;
int c = 4;
c = fun(c+1);
return a;
}

int main()
{
int x = 5;
float a = 5.3;
a = foo(a, x);
x =fun(x);
x =fun(x+2);
printf("%0.2f\n", a);

return 0;
}
