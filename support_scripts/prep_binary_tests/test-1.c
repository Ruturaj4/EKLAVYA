#include <stdio.h>

float foo(float a)
{
a = 5.7;
return a;
}

int main()
{
int x = 5;
float a = 5.3;
a = foo(a);
printf("%0.2f\n", a);

return 0;
}
