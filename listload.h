#include <stdio.h>
#include <iostream>
#include <list>
#include <vector>
#include <map>
#include <pcap/pcap.h>
#include <mysql/mysql.h>
#include "dbmanage.h"
#include "mac.h"
#include "packframes.h"
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <stdlib.h>



#define WHITEAP 1
#define WHITESTATION 2
#define BLACKAP 3
#define BLACKSTATION 4

#define RTHLENGTH   12



class listLoad
{

    private:
    uint8_t cmp_v = 1;
    MYSQL_ROW row;
    mac tempMac;

 //--------------------------get pkt info(rth+mac)

    //packframes pktForm;
    packframes PFrame;
    packframes::rth* rthFrame;
    #pragma pack(push,1)
    typedef struct recv_info{
        mac apMac;
        char rss;
        uint16_t channel;
        mac stationMac;
    }info;
    info infoForm;
    typedef struct black_list{
        uint8_t apMac[6];
        int channel;
        int blockStat;
        uint8_t stMac[6];
        int apAuth;
        int apCipher;
        int apEnc;
        int macType;

    }bList;
    bList blkStruct;
    #pragma pack(pop)
    typedef std::map<int,bList>blk_list;
    blk_list BlackList;
    typedef std::map<int,bList>::iterator blk_list_iter;
    blk_list_iter BlackIter;
    typedef std::map<int,info>pkt_info;
    typedef std::map<int,info>::iterator pkt_info_iter;
//--------------------------------------------------

    //MYSQL_RES *listRes;
    typedef std::map<int,std::string> wApMap;
    wApMap CipwAp;//int,string
    typedef std::map<int,std::string>::iterator wApIter;

    typedef std::map<int,std::string> wStMap;
    wStMap CipwSp;//int,string
    typedef std::map<int,std::string>::iterator wStIter;

    typedef std::map<int,std::string> bStMap;
    bStMap CipbAp;//int,string
    typedef std::map<int,std::string>::iterator bAPIter;




    public:
        listLoad();
        void convMac(int macFlag,std::string recvMac);
        int initTbl(MYSQL_RES* lRes,int macField);
        void getPktInfo(uint8_t* pktData);

};





