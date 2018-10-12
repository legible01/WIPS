#ifndef USRFUNC_H
#define USRFUNC_H
#pragma once
#include <arpa/inet.h>
#include <iostream>
#include <cstdint>

#include "packframes.h"
#include "aaa.h"
#include "listload.h"
#include "wonsang.h"
#include "bbb.h"





class usrfunc
{
public:
    uint8_t* pktPoint;
    packframes::rth* RTHeader;
    packframes::FC* frameCtrl;
    struct packframes::ManagementFrame *mgmtFrame;
    listload::bwList bwDatas;
    bool WHTFlag = false; //true in whitelisted packet
    bool BLKFlag = false; //true in blacklisted packet

    //listload* lLoad;
    //listload t1t1;

    typedef struct extPktInfo{


    };



    usrfunc(uint8_t *packet);
    void fakeAp(listload& listMan2);
    int Cipher(uint8_t cipher);
    int Auth(uint8_t auth);
    int misconfigureAP(listload& listMan2);
    void test_viewFunc(listload& listMan2);
    void macCmp(listload& listMan2);
    void adhocFunc(listload& listMan2);


};

#endif // USRFUNC_H
