#pragma once
#include <iostream>
//#include <ctypes>
//#include "pktpassway.h"
#include "listload.h"
#include "dbmanage.h"
#include "devsearch.h"
#include "packframes.h"
#include "usrfunc.h"
#include <mutex>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

class pktPassWay
{
    //char *correct_dev(int argu_count,char *argu_vector);
private:
public:
    //std::mutex mtx_lock;
    int main(listload& listMan,dbmanage& wipsDB,std::mutex& mtx_lock);
    char *correct_dev(int argCnt,char *argVector);
    void pktFilter(uint8_t *pktData,listload& listMan1,dbmanage& wipsDB1,std::mutex& mtx_lock1);
    listload memList;
};
