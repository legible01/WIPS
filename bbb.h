#ifndef BBB_H
#define BBB_H
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#pragma pack(push,1)

typedef struct Radiotap_Header
{
    u_int8_t Header_Revision;
    u_int8_t Header_Pad;
    u_int16_t Header_Length;

}Radiotap_Header;

typedef struct FrameControl
{
    u_int8_t ProVer:2;
    u_int8_t Type:2;
    u_int8_t Subtype:4;
    u_int8_t ToDs:1;
    u_int8_t FromDs:1;
    u_int8_t MoreFlag:1;
    u_int8_t Retry:1;
    u_int8_t PowerMgmt:1;
    u_int8_t MoreData:1;
    u_int8_t Wep:1;
    u_int8_t Rsvd:1;
 } FrameControl;

typedef struct Manage
{
    FrameControl Frame_control;
    u_short Duration;
    u_int8_t des[6];
    u_int8_t src[6];
    u_int8_t BSS[6];
    u_short Sequence;


    struct Wireless_LAN{
        u_int8_t Timestamp[8];
        u_short Beacon;
        struct Capavility{
            u_int8_t ESS:1;
            u_int8_t IBSS:1;
            u_int8_t CFP:2;
            u_int8_t Privacy:1;
            u_int8_t Short_Preamble:1;
            u_int8_t PBCC:1;
            u_int8_t Channel_Agility:1;
            u_int8_t Spectrum_Agility:1;
            u_int8_t Short_Slot:1;
            u_int8_t APSD:1;
            u_int8_t Raido_measurement:1;
            u_int8_t DSSS_OFDM:1;
            u_int8_t DBA:1;
        }Capavility;

    }Wireless_LAN;

}Manage;

#pragma pack(pop)
#endif // BBB_H
