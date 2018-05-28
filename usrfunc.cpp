#include "usrfunc.h"

usrfunc::usrfunc(uint8_t *packet)
{
    this->pktPoint = packet;
    this->RTHeader = (packframes::rth*)packet;
    this->frameCtrl = (packframes::FC*)((uint8_t*)(packet+RTHeader->rth_length));
    this->mgmtFrame = (packframes::ManagementFrame*)((uint8_t*)(packet+RTHeader->rth_length));
}

void usrfunc::fakeAp(void)
{
    uint8_t* pktPoint2 = this->pktPoint;

    struct packframes::WifiName *wifiName;
           //BSSID***********************************************************************************//
           printf("BSSID: ");
           for(int i=0; i<6; i++)
           {
               printf("%02x ", mgmtFrame->addr3[i]);
           }
           printf("\n");

           //SSID************************************************************************************//
           pktPoint2 += (RTHeader->rth_length + sizeof(struct packframes::ManagementFrame) + sizeof(struct packframes::BeaconFrameBody) + sizeof(struct packframes::TagBody));
           wifiName = (struct packframes::WifiName *)pktPoint2;
           printf("SSID:  ");
           for(int i=0; i<32; i++)
           {
               if(pktPoint2[i] == 1)
                   break;

               printf("%c", wifiName->ssid[i]);
           }
   printf("\n\n");

}
