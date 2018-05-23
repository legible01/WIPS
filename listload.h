#include <cstdio>
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
    typedef struct recv_info{
        mac apMac;
        char rss;
        uint16_t channel;
        mac stationMac;
    }info;
    info infoForm;

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
        int initTbl(MYSQL_RES* lRes,int macField);
        void getPktInfo(uint8_t* pktData);

};





