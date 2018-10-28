#include "deauth.h"

deauth::deauth()
{

}

void deauth::testFunc11(listload& listMan,dbmanage& wipsDB,std::mutex& mtx_lock1)
{
    printf("deauth testFunc\n");
    char tempbuf[250] = {0,};
    char chanbuf[250] = {0,};
    //std::mutex mtx_lock;

    listload::bw_list::iterator it;
    printf("CHECK fakeAp\n\n");
    while(1){
         mtx_lock1.lock();
         for(it = listMan.BlackList.begin();it !=listMan.BlackList.end();it++){
            //printf("view func first %d\n",it->first);
            bwDatas = (listload::bwList)it->second;
            deauthInfo.channel = bwDatas.channel;
            deauthInfo.blockStat = bwDatas.blockStat;
            if(deauthInfo.blockStat == 1 ){
                memcpy(&(deauthInfo.stMac),&(bwDatas.stMac),6);
                memcpy(&(deauthInfo.apMac),&(bwDatas.apMac),6);
            }else if(deauthInfo.blockStat == 0){
                memcpy(&(deauthInfo.apMac),&(bwDatas.apMac),6);
                memset(&(deauthInfo.stMac),0,6);

            }
            sprintf(chanbuf,"sudo iwconfig wlan3 channel %d",deauthInfo.channel);
            int ret1 = system(chanbuf);
            sprintf(tempbuf,"aireplay-ng -0 20 -a %02X:%02X:%02X:%02X:%02X:%02X wlan3",deauthInfo.apMac[0],deauthInfo.apMac[1],deauthInfo.apMac[2],deauthInfo.apMac[3],deauthInfo.apMac[4],deauthInfo.apMac[5]);
            int ret2 = system(tempbuf);
            //--ignore-negative-one

        memset(&(tempbuf[0]),0,250);
        memset(&(chanbuf[0]),0,250);
        }
         mtx_lock1.unlock();
         sleep(0.01);
    }

}



