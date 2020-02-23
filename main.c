#include <stdio.h>
#include <string.h>

const char text[] = "12345678";

int main()
{
    size_t len = strlen(text);
    printf("%lu\n", len);
    return 0;
}
