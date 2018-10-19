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
#include <map>

#define RTHEADERSIZE 12

class usrfunc
{
public:
    #pragma pack(push,1)
    packframes PFrame;
    uint8_t* pktPoint;
    packframes::rth* RTHeader;
    packframes::FC* frameCtrl;
    struct packframes::ManagementFrame *mgmtFrame;
    listload::bwList bwDatas;
    bool WHTFlag = false; //true in whitelisted packet
    bool BLKFlag = false; //true in blacklisted packet
    bool storFlag = false;
    uint8_t cliMac[6];
    uint8_t APMac[6];

    typedef struct currentPktData{

    }curPktData;
    #pragma pack(pop)
    //listload* lLoad;
    //listload t1t1;


    typedef struct extPktInfo{       
        uint8_t apMac[6];
        int channel;
        int blockStat;
        uint8_t stMac[6];
        int apAuth;
        int apCipher;
        int apEnc;
        int macType;
        uint8_t adHocStat;
        char ssid[32];


    }extPktDatas;
    extPktDatas exPkt;

    char atkType[250] = {0,};


    usrfunc(uint8_t *packet);
    void fakeAp(listload& listMan2);

    //---------------------------hyunseok
    int Cipher(uint8_t cipher);
    int Auth(uint8_t auth);
    int misconfigureAP(listload& listMan2);
    //----------------------------------------

    void test_viewFunc(listload& listMan2);

    //-----------------wonsang--------------
    void macCmp(listload& listMan2);
    //-----------------------------------------

    //-----------------minseok-------------
    void adhocFunc(listload& listMan2);
   // ---------------------------------------

    void retMacAdr(void);
    void getCurPktData(listload& listMan2);
    void radioGetData(void);
    void inputCurPkt(listload& listMan2,dbmanage& wipsDB2);
    int hzToCnl(uint16_t recvhz);

};

#endif // USRFUNC_H
