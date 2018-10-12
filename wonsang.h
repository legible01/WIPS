#ifndef WONSANG_H
#define WONSANG_H

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#pragma pack(push, 1)
/*struct RadiotapHeader
{
    uint8_t    reversion;
    uint8_t    pad;
    uint16_t   length;

};

typedef struct FrameCtrl
{
    uint8_t   protocolVer    : 2;
    uint8_t   type           : 2;
    uint8_t   subType        : 4;
    uint8_t   toDs           : 1;
    uint8_t   fromDs         : 1;
    uint8_t   moreFlag       : 1;
    uint8_t   retry          : 1;
    uint8_t   powerMgmt      : 1;
    uint8_t   moreData       : 1;
    uint8_t   protectedFrame : 1;
    uint8_t   order          : 1;
}FC;

struct ManagementFrame
{
           FC  frameCtrl;  //2 bytes
           uint16_t   duration;   //2 bytes
           uint8_t    addr1[6];   //6 bytes
           uint8_t    addr2[6];   //6 bytes
           uint8_t    addr3[6];   //6 bytes
           //uint16_t   seq_ctrl;   //2 bytes
           uint16_t   seq      : 12;   //12 bits
           uint8_t    fragment :  4;   // 4 bits
};*/
#pragma pack(pop)

void macCmp(const u_char *);
void printMac(const u_char *, int);

#endif // WONSANG_H
