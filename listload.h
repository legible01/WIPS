#include <cstdio>
#include <iostream>
#include <list>
#include <pcap/pcap.h>
#include <mysql/mysql.h>
#include "dbmanage.h"

#define WHITEAP 1
#define WHITESTATION 2
#define BLACKAP 3
#define BLACKSTATION 4



class listLoad
{

    private:
    //MYSQL_RES *listRes;


    public:
        listLoad();
        int initList(int tblType);

};





