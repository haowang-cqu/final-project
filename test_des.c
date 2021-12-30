#include "des.h"
#include <stdio.h>
#include <stdlib.h>

int main()
{
    Block key, password;
    key.c[0] = 'd';
    key.c[1] = 'e';
    key.c[2] = 's';
    key.c[3] = '@';
    key.c[4] = 'k';
    key.c[5] = 'e';
    key.c[6] = 'y';
    key.c[7] = '\0';
    password.c[0] = 'P';
    password.c[1] = '@';
    password.c[2] = 's';
    password.c[3] = 's';
    password.c[4] = 'w';
    password.c[5] = 'o';
    password.c[6] = 'r';
    password.c[7] = 'd';
    uint64_t cipher = des(password.l, key.l, e);
    printf("%llx\n", cipher);
    return 0;
}