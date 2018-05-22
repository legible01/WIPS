#include <iostream>
#include "pktpassway.h"


int main(int argc, char *argv[])
{
    printf("helloworld");
    char a = 0xba;
    printf("ba is %d",a);
    pktPassWay test;
    //need argc
    test.main();
    return 0;
}
