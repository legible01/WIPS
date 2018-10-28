#ifndef DEAUTH_H
#define DEAUTH_H

#include <cstdio>
#include <iostream>
#include "listload.h"
#include "dbmanage.h"
#include <stdlib.h>
#include <map>
#include <cstring>
#include <unistd.h>
#include <mutex>


class deauth
{
public:
    int numTest;
    listload::bwList bwDatas;
    typedef struct deauthSet{
        uint8_t apMac[6];
        int channel;
        int blockStat;
        uint8_t stMac[6];
    }deauthSet;
    deauthSet deauthInfo;
    deauth();
    void testFunc11(listload& listMan,dbmanage& wipsDB,std::mutex& mtx_lock1);
};

#endif // DEAUTH_H
