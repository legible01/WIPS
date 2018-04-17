#include <cstdio>
#include <iostream>
#include <list>
#include <vector>
#include <map>
#include <pcap/pcap.h>
#include <mysql/mysql.h>
#include "dbmanage.h"
#include "mac.h"


#define WHITEAP 1
#define WHITESTATION 2
#define BLACKAP 3
#define BLACKSTATION 4



class listLoad
{

    private:
    MYSQL_ROW row;
    mac tempMac;

    //MYSQL_RES *listRes;
    typedef std::map<int,std::string> wApMap;
    wApMap CipwAp;//int,string
    typedef std::map<int,std::string>::iterator cipWApIter;

    typedef std::map<int,std::string> wStMap;
    wStMap CipwSp;//int,string
    typedef std::map<int,std::string>::iterator cipWStIter;

    typedef std::map<int,std::string> bStMap;
    bStMap CipbAp;//int,string
    typedef std::map<int,std::string>::iterator cipBAPIter;


    public:
        listLoad();
        int initTbl(MYSQL_RES* lRes,int macField);

};





