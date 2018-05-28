#include <iostream>

//#include <ctypes>
//#include "pktpassway.h"
#include "listload.h"
//#include "dbmanage.h"
#include "devsearch.h"
#include "packframes.h"
#include "usrfunc.h"
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
class pktPassWay
{
    //char *correct_dev(int argu_count,char *argu_vector);
private:
public:
    int main(void);
    char *correct_dev(int argCnt,char *argVector);
    void pktFilter(uint8_t *pktData);
    listLoad memList;
};
