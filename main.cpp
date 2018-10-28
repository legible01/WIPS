#include <iostream>
#include "listload.h"
#include "dbmanage.h"
#include "pktpassway.h"
#include "deauth.h"
#include <thread>
using namespace std;

#define BLACKLISTFLAG 10
#define WHITELISTFLAG 11

int main(int argc, char *argv[])
{
    char a = 0xba;
    dbmanage wipsDB;
    listload listMan;
    pktPassWay test;
    std::mutex mtx_lock;
    deauth dd;
    printf("BLACKLIST ENROLL\n");


    int stat =  listMan.initlist(wipsDB.dbQuery("SELECT * FROM wips_black_blacklist"),BLACKLISTFLAG);
    printf("WHITELIST ENROLL\n");
    int stat1 =  listMan.initlist(wipsDB.dbQuery("SELECT * FROM wips_white_whitelist"),WHITELISTFLAG);
    //thread t1{&pktPassWay::main,&test,listMan,wipsDB};
    thread t1([&](){test.main(listMan,wipsDB,mtx_lock);});
    thread t2([&](){dd.testFunc11(listMan,wipsDB,mtx_lock);});
    //t1.join();
    t2.join();
    return 0;
}

