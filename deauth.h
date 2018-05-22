#ifndef DEAUTH_H
#define DEAUTH_H
#include <iostream>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <pcap/pcap.h>
#include "mac.h"
#define Client 1
#define AP     2

class deauth
{
private:
    int length;
    //apAddr mac;
    //stAddr mac;
#pragma pack(push,1)
    typedef struct frameControl{
        uint8_t version :2;
        uint8_t type :2;
        uint8_t subtype :4;
        uint8_t flags;
    }packFc;

    typedef struct managementFrame{
       packFc fC;
       uint16_t duration;
       uint8_t dstAdr[6];
       uint8_t srcAdr[6];
       uint8_t bssid[6];
       uint16_t seqCtl;//init 0
    }mgMtHdr;

    typedef struct deAuth_pkt{
      mgMtHdr mgmt;
      uint16_t code;
      uint32_t fcs;//ff?
    }deauthPkt;
deauthPkt dpack;

#pragma pack(pop)
public:
    deauth();
    void main_deauth(char * devName);
    char* ret_deauth(void);
    void send_pack(void);
    void send_deauth(uint8_t*addr1,uint8_t*addr2,int objPkt);
    void create_pack(uint8_t* client, uint8_t*ap,int objPkt);
};

#endif // DEAUTH_H
