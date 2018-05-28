#ifndef USRFUNC_H
#define USRFUNC_H
#include <arpa/inet.h>
#include <iostream>
#include <cstdint>

#include "packframes.h"



class usrfunc
{
public:
    uint8_t* pktPoint;
    packframes::rth* RTHeader;
    packframes::FC* frameCtrl;
    struct packframes::ManagementFrame *mgmtFrame;


    usrfunc(uint8_t *packet);
    void fakeAp(void);

};

#endif // USRFUNC_H
