#ifndef USRFUNC_H
#define USRFUNC_H
#include <arpa/inet.h>
#include <iostream>
#include <cstdint>

#include "packframes.h"
#include "aaa.h"



class usrfunc
{
public:
    uint8_t* pktPoint;
    packframes::rth* RTHeader;
    packframes::FC* frameCtrl;
    struct packframes::ManagementFrame *mgmtFrame;


    usrfunc(uint8_t *packet);
    void fakeAp(void);
    void misconfigureAP (const uint8_t *data);
    int Cipher(uint8_t cipher);
    int Auth(uint8_t auth);

};

#endif // USRFUNC_H
