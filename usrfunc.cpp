#include "usrfunc.h"

usrfunc::usrfunc(uint8_t *packet)
{
    this->pktPoint = packet;
    this->RTHeader = (packframes::rth*)((uint8_t*)packet);
    this->frameCtrl = (packframes::FC*)((uint8_t*)(packet+RTHeader->rth_length));
    this->mgmtFrame = (packframes::ManagementFrame*)((uint8_t*)(packet+RTHeader->rth_length));
    memset(this->APMac,0,6);
    memset(this->cliMac,0,6);
    //when mgmt then set ap,cli
    //need set um....
}
void usrfunc::fakeAp(listload& listMan2)
{
    WHTFlag = false; //true in whitelisted packet
    BLKFlag = false; //true in blacklisted packet
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
           uint8_t* lengthPnt = ((uint8_t*)pktPoint2) - 1;
           printf("cur leng is %d\n",*lengthPnt);
           printf("SSID:  ");
           for(int i=0; i<32; i++)
           {
               if(pktPoint2[i] == 1)
                   break;

               printf("%c", wifiName->ssid[i]);

           }
   printf("\n\n");
   int cmpFlag = 0;
   int macCmpFlag = 0;
   //uint8_t cmpArray[6];
   listload::bw_list::iterator it;

   printf("-------------------------------------------------\n");
     //wht list!
   printf("CHECK fakeAp\n\n");
    for(it = listMan2.WhiteList.begin();it !=listMan2.WhiteList.end();it++){
       //printf("view func first %d\n",it->first);
       bwDatas = (listload::bwList)it->second;
       macCmpFlag = memcmp(&(bwDatas.apMac),&(mgmtFrame->addr3),6);
       if(macCmpFlag == 0){
           printf("cmp ssid %s\n",bwDatas.ssid);

           cmpFlag = memcmp(&(bwDatas.ssid),&(wifiName->ssid),*lengthPnt);
           if(cmpFlag == 0){
               printf("LISTED SSID!(WHITE)\n");
               WHTFlag = true;
               break;
               //alreay have white list OK.
           }
       }
   }

   cmpFlag = 0;
   macCmpFlag = 0;
   if(WHTFlag == false){
       printf("NOT LISTED SSID(WHITE) \n");
       cmpFlag = 0;
       //uint8_t cmpArray[6];
       listload::bw_list::iterator it1;


                   //blk list!
       for(it1 = listMan2.BlackList.begin();it1 !=listMan2.BlackList.end();it1++){
             //printf("view func first %d\n",it->first);
             bwDatas = (listload::bwList)it1->second;
             //printf("cmp with %02x %02x %02x %02x %02x %02x\n",bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
             //printf("check blk SSID\n");
             macCmpFlag = memcmp(&(bwDatas.apMac),&(mgmtFrame->addr3),6);
             if(macCmpFlag == 0){
                 printf("cmp ssid %s\n",bwDatas.ssid);

                 cmpFlag = memcmp(&(bwDatas.ssid),&(wifiName->ssid),*lengthPnt);
                 if(cmpFlag == 0){
                     printf("LISTED SSID(BLACK)\n");
                     BLKFlag = true;
                     break;
                     //alreay have black list OK.
                 }
             }

        }

     }
     memset(&(exPkt.ssid),0,32);
     memcpy(&(exPkt.ssid),&(wifiName->ssid),*lengthPnt);
     printf("exPkt ssid %s\n",exPkt.ssid);
     printf("NOT LISTED SSID(BLACK) \n");
     if(WHTFlag == false && BLKFlag == false){
         printf("\ndisordered!(FAKE AP)\n\n");
         storFlag = true;
         char tempbuf[250] = {0,};
         sprintf(tempbuf,"%s FAKEAP",atkType);
         sprintf(atkType,"%s",tempbuf);
         //start function(structure write and throw map,db)

     }


}




int usrfunc::Cipher(uint8_t cipher)
{
    switch (cipher)//Group Cipher Suite(broad,multicast) Type
                    {

                    case 0:
                        printf("Group Cipher Suite 사용\n");
                        cipher = GROUP_CIPHER_SUITE; //Group Cipher Suite flsg:21
                        break;

                    case 1:
                        printf("WEP-40 사용\n");
                        cipher = WEP40; //WEP-40 flag:12
                        break;

                    case 2:
                        printf("TKIP 사용\n");
                        cipher = TKIP; //TKIP flag:13
                        break;

                    case 3:
                        printf("예약 사용\n");
                        cipher = C_RESERVATON; //예약 flag:14
                        break;

                    case 4:
                        printf("CCMP 사용\n");
                        cipher = CCMP; //CCMP flag:15
                        break;

                    case 5:
                        printf("WEP-104 사용\n");
                        cipher = WEP104; //WEP-104 flag:16
                        break;

                printf("Cipher fun:%d\n", cipher);
                    }
    return(cipher);
}

int usrfunc::Auth(uint8_t auth)
{
    switch (auth)
    {
    case 0:
        printf("예약 사용\n");
        auth = A_RESERVATON;//flag:17
        break;

    case 1:
        printf("802.1X 인증\n");
        auth = A_8021X;//flag:18
        break;

    case 2:
        printf("PSK 인증\n");
        auth = PSK;//flag:19
        break;

    default:
        printf("...\n");
        break;
    }
    return(auth);

}


int usrfunc::misconfigureAP(listload& listMan2)
{

    WHTFlag = false; //true in whitelisted packet
    BLKFlag = false; //true in blacklisted packet
    uint8_t *data = this->pktPoint;
    struct RadiotapHeader *rH;//
    struct RadiotapHeaderFlag *rF;//
    struct ManagementFrame *mF;//
    struct FrameCtrl *fC;//
    struct OptionField *oF;//
    struct Rsn *rsn;//
    struct VendorSpecific *vS;//
    struct SecurityMethod sM;
    struct SecurityFlag sF;
    struct SecurityFlag listSF;
    //struct AkmSuiteSelector *aS;
   // struct PairwiseCipherSuiteSelector *pS;


    rH = (struct RadiotapHeader *)data;
    rF = (struct RadiotapHeaderFlag *)data;
    mF = (struct ManagementFrame *)(data + rH->length);
    fC = (struct FrameCtrl *)(data + rH->length);
    oF = (struct OptionField *)(data + rH->length + sizeof(struct ManagementFrame) + sizeof(struct BeaconFrameBody));
    rsn = (struct Rsn *)data;
    vS = (struct VendorSpecific *)data;


    printf("--------------------------------\n");
    printf("AP RULE CHECK\n\n");

    uint8_t apMac[6]; //BSS = AP MAC
    //printf("ok\n\n");
    sM.wep = fC->protectedFrame;
    //int16_t tpcss;

/*비콘 아닐때도 48, 221있는듯? 221은 확실히있음
그럼 비콘일때 ap mac 잡아버리면 ap mac 없는 패킷도 나옴 암호는 나오지만
그냥 비콘일때로 통일?*/
    apMac[0] = mF->addr3[0];
    apMac[1] = mF->addr3[1];
    apMac[2] = mF->addr3[2];
    apMac[3] = mF->addr3[3];
    apMac[4] = mF->addr3[4];
    apMac[5] = mF->addr3[5];
    printf("AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",apMac[0],apMac[1],apMac[2],apMac[3],apMac[4],apMac[5]);

            if(fC->subType == 8 && fC->type == 0)//BeaconFrame
            {
                apMac[0] = mF->addr3[0];
                apMac[1] = mF->addr3[1];
                apMac[2] = mF->addr3[2];
                apMac[3] = mF->addr3[3];
                apMac[4] = mF->addr3[4];
                apMac[5] = mF->addr3[5];


                while((oF->elementId | oF->length )!= 0)//OptionFrame
                {
                    if(oF->elementId == 48)//RSN ID:48
                    {
                        rsn = (Rsn *)(uint8_t*)oF;

                        sM.gCSS[0] = rsn->gCSS[0];//00-0f-ac
                        sM.gCSS[1] = rsn->gCSS[1];
                        sM.gCSS[2] = rsn->gCSS[2];
                        sM.gCSS[3] = rsn->gCSS[3];//Type


                        {


                           // tpcss = rsn->pCSC; //이거지우면 안돌아감 왜??/

                            switch (rsn->pCSC)
                           {
                           case 1:
                               //printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[0], rsn->pCSS.pOUI[1], rsn->pCSS.pOUI[2]);//PairwiseCipherSuiteSelector OUI
                               //printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[3]);//PairwiseCipherSuiteSelector OUISC);
                               sM.pCSS[3] = rsn->pCSS.pOUI[3];
                               //printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[0], rsn->aSS[1], rsn->aSS[2]);//AKM OUI ID=48 -> WPA-2
                               //printf("AKM TYPE : %02x\n",rsn->aSS[3]);//AKM TYPE ID=48 -> WPA-2
                               sM.aSS[3] = rsn->aSS[3];
                               sM.aSC[0] = rsn->aSC[0];
                               sM.aSC[1] = rsn->aSC[1];
                               break;

                           case 2:
                               //printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[4], rsn->pCSS.pOUI[5], rsn->pCSS.pOUI[6]);//PairwiseCipherSuiteSelector OUI
                               //printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[7]);//PairwiseCipherSuiteSelector OUISC);
                               sM.pCSS[3] = rsn->pCSS.pOUI[7];
                               //printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[4], rsn->aSS[5], rsn->aSS[6]);//AKM OUI ID=48 -> WPA-2
                               //printf("AKM TYPE : %02x\n",rsn->aSS[7]);//AKM TYPE ID=48 -> WPA-2
                               sM.aSS[3] = rsn->aSS[7];
                               sM.aSC[0] = rsn->aSC[2];
                               sM.aSC[1] = rsn->aSC[3];
                               break;

                           case 3:
                               //printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[8], rsn->pCSS.pOUI[9], rsn->pCSS.pOUI[10]);//PairwiseCipherSuiteSelector OUI
                               //printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[11]);//PairwiseCipherSuiteSelector OUISC);
                               sM.pCSS[3] = rsn->pCSS.pOUI[11];
                              // printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[8], rsn->aSS[9], rsn->aSS[10]);//AKM OUI ID=48 -> WPA-2
                               //printf("AKM TYPE : %02x\n",rsn->aSS[11]);//AKM TYPE ID=48 -> WPA-2
                               sM.aSS[3] = rsn->aSS[7];
                               sM.aSC[0] = rsn->aSC[4];
                               sM.aSC[1] = rsn->aSC[5];
                               break;

                           case 4:
                               //printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[12], rsn->pCSS.pOUI[13], rsn->pCSS.pOUI[14]);//PairwiseCipherSuiteSelector OUI
                               //printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[15]);//PairwiseCipherSuiteSelector OUISC);
                               sM.pCSS[3] = rsn->pCSS.pOUI[15];
                               //printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[12], rsn->aSS[13], rsn->aSS[14]);//AKM OUI ID=48 -> WPA-2
                               //printf("AKM TYPE : %02x\n",rsn->aSS[15]);//AKM TYPE ID=48 -> WPA-2
                               sM.aSS[3] = rsn->aSS[15];
                               sM.aSC[0] = rsn->aSC[6];
                               sM.aSC[1] = rsn->aSC[7];
                               break;

                           default:
                               printf("???????????????????????????????????????????????????????????????????????/\n");
                               break;
                           }


                         if(sM.aSC[0] != 0x01)
                         {
                            switch (sM.aSC[0])
                          {
                           /*case 1:
                               printf("1111111111111111111111111111111111111111\n");
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[0], rsn->aSS[1], rsn->aSS[2]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPEdd : %02x\n",rsn->aSS[3]);//AKM TYPE ID=48 -> WPA-2
                             //  TYPE[2] = rsn->aSS[3];
                               break;*/

                          case 2:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[4], rsn->aSS[5], rsn->aSS[6]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[7]);//AKM TYPE ID=48 -> WPA-2
                              sM.aSS[3] = rsn->aSS[7];
                              break;

                          case 3:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[8], rsn->aSS[9], rsn->aSS[10]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[11]);//AKM TYPE ID=48 -> WPA-2
                              sM.aSS[3] = rsn->aSS[11];
                              break;

                          case 4:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[12], rsn->aSS[13], rsn->aSS[14]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[15]);//AKM TYPE ID=48 -> WPA-2
                              sM.aSS[3] = rsn->aSS[15];
                              break;

                          default:
                              //printf("???????????????????????????????????????????????????????????????????????/\n");
                              break;
                          }
                         }
                        }

                        sM.aSS[0] = rsn->aSS[0];//00-0f-ac
                        sM.aSS[1] = rsn->aSS[1];
                        sM.aSS[2] = rsn->aSS[2];

                     }

                    else if(oF->elementId == 221)//Vendor specific ID:221
                    {
                        vS = (VendorSpecific *)(uint8_t*)oF;


                        if(vS->oUI[0] == 0x00 && vS->oUI[1] == 0x50 && vS->oUI[2] == 0xf2)//OUI 00-50-f2
                        {
                            if(vS->vST == 0x01)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {

                            sM.oUI[0] = vS->oUI[0];//00-50-f2
                            sM.oUI[1] = vS->oUI[1];
                            sM.oUI[2] = vS->oUI[2];
                            sM.mCSS[3] = vS->mCSS[3]; //Type =1 WPA Information

                            switch (vS->uCSC)
                            {
                            case 1:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[0], vS->uCSS[1], vS->uCSS[2]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[3]);//Unicast Cipher Suite TYPE ID:221
                                sM.uCSS[3] = vS->uCSS[3];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[0], vS->aSS[1], vS->aSS[2]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[3]);//AKM TYPE ID=221 -> WPA-1
                                sM.aKMS[3] = vS->aSS[3];
                                sM.aKMC[0] = vS->aSC[0];
                                sM.aKMC[1] = vS->aSC[1];
                                break;

                            case 2:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[4], vS->uCSS[5], vS->uCSS[6]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[7]);//Unicast Cipher Suite TYPE ID:221
                                sM.uCSS[3] = vS->uCSS[7];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[4], vS->aSS[5], vS->aSS[6]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[7]);//AKM TYPE ID=221 -> WPA-1
                                sM.aKMS[3] = vS->aSS[7];
                                sM.aKMC[0] = vS->aSC[2];
                                sM.aKMC[1] = vS->aSC[3];
                                break;

                            case 3:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[8], vS->uCSS[9], vS->uCSS[10]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[11]);//Unicast Cipher Suite TYPE ID:221
                                sM.uCSS[3] = vS->uCSS[11];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[8], vS->aSS[9], vS->aSS[10]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[11]);//AKM TYPE ID=221 -> WPA-1
                                sM.aKMS[3] = vS->aSS[11];
                                sM.aKMC[0] = vS->aSC[4];
                                sM.aKMC[1] = vS->aSC[5];
                                break;

                            case 4:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[12], vS->uCSS[13], vS->uCSS[14]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[15]);//Unicast Cipher Suite TYPE ID:221
                                sM.uCSS[3] = vS->uCSS[15];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[12], vS->aSS[13], vS->aSS[14]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[15]);//AKM TYPE ID=221 -> WPA-1
                                sM.aKMS[3] = vS->aSS[15];
                                sM.aKMC[0] = vS->aSC[6];
                                sM.aKMC[1] = vS->aSC[7];
                                break;

                            default:
                                printf("???????????????????????????????????????????????????????????????????????/\n");
                                break;
                            }


                            if(sM.aKMC[0] != 0x01)
                            {

                                switch (sM.aKMC[0])
                               {

                               /*case 1:
                                    printf("111111111111111111111111111111111111111\n");
                                    printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[0], vS->aSS[1], vS->aSS[2]);//AKM OUI ID=221 -> WPA-1
                                    printf("AKM TYPE : %02x\n",vS->aSS[3]);//AKM TYPE ID=221 -> WPA-1
                                  //  TYPE[5] = vS->aSS[3];
                                    break;*/

                               case 2:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[4], vS->aSS[5], vS->aSS[6]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[7]);//AKM TYPE ID=221 -> WPA-1
                                   sM.aKMS[3] = vS->aSS[7];
                                   break;

                               case 3:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[8], vS->aSS[9], vS->aSS[10]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[11]);//AKM TYPE ID=221 -> WPA-1
                                   sM.aKMS[3] = vS->aSS[11];
                                   break;

                               case 4:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[12], vS->aSS[13], vS->aSS[14]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[15]);//AKM TYPE ID=221 -> WPA-1
                                   sM.aKMS[3] = vS->aSS[15];
                                   break;

                               default:
                                   printf("???????????????????????????????????????????????????????????????????????/\n");
                                   break;
                               }
                         }


                            }

                            if(vS->vST == 0x02)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {

                            sM.oUI[0] = vS->oUI[0];//00-50-f2
                            sM.oUI[1] = vS->oUI[1];
                            sM.oUI[2] = vS->oUI[2];
                            }
                        }
                    }
                    oF = (OptionField *)((uint8_t*)oF+sizeof(OptionField)+oF->length);
                }
            }

            //*********************Flag set*******************
            if(sM.oUI[0] == 0x00 && sM.oUI[1] == 0x50 && sM.oUI[2] == 0xf2 &&
               sM.gCSS[0] == 0x00 && sM.gCSS[1] == 0x0f && sM.gCSS[2] == 0xac)//OUI 00-50-f2 && OUI 00-0f-ac -> WPA2
            {
                //a = 20; //WPA-2 flsg:20
                sF.enc = WPA2;
                printf("WPA-2: %d\n", sF.enc);
                //sF.enc = 20; //WPA-2 flsg:20
                //printf("aaaaaaaaaaaaaaaaaaaaaaaaa\n");
                //printf("Group Cipher Suite Selector: %d\n",sM.gCSS[3]);//Group Cipher Suite Selector(multicast) Type
                sF.groupCipher = Cipher(sM.gCSS[3]);
               // printf("Flag: %d\n", sF.groupCipher);

               // printf("Pairwise Cipher Suite Selector: %d\n",sM.pCSS[3]);//Pairwise Cipher Suite Selector(unicast) Type
                sF.pairwiseCipher = Cipher(sM.pCSS[3]);
               // printf("Flag: %d\n", sF.pairwiseCipher);

                //printf("AKM Suite Selector: %d\n",sM.aSS[3]);//Authentication and Key Management Type
                sF.auth = Auth(sM.aSS[3]);
               /// printf("Flag: %d\n", sF.auth);
            }

            else if(sM.oUI[0] == 0x00 && sM.oUI[1] == 0x50 && sM.oUI[2] == 0xf2)//OUI 00-50-f2 -> WPA-1
            {
               // printf("WPA-1\n");
                sF.enc = WPA1; //WPA-1 flsg:10
                printf("WPA-1: %d\n", sF.enc);

                printf("Group Cipher Suite Selector: %d\n",sM.mCSS[3]);//Group Cipher Suite Selector(multicast) Type
                sF.groupCipher = Cipher(sM.mCSS[3]);
                printf("Flag: %d\n", sF.groupCipher);

                printf("Pairwise Cipher Suite Selector: %d\n",sM.uCSS[3]);//Pairwise Cipher Suite Selector(unicast) Type
                sF.pairwiseCipher = Cipher(sM.uCSS[3]);
                //printf("Flag: %d\n", sF.pairwiseCipher);

                printf("AKM Suite Selector: %d\n",sM.aKMS[3]);//Authentication and Key Management Type
                sF.auth = Auth(sM.aKMS[3]);
              //  printf("Flag: %d\n", sF.auth);
            }

            if(sM.wep == 1)//WEP
            {
                sF.enc = WEP; //WEP flsg:1
                printf("WEP flag: %d\n", sF.enc);
            }

            if(sM.wep == 0 && rsn->elementId != 48 && vS->elementId != 221)//OPEN
            {
                sF.enc = OPEN; //OPEN flsg:0
                printf("OPEN flag: %d\n", sF.enc);
            }

            //###################TYPE########################
            //printf("##############################\n");
            //ID:48 WPA-2
            //printf("GROUP:%d\n",sM.gCSS[3]);
            //printf("PAIRWISE COUNT:%02x-%02x\n",sM.pCSC);
            printf("PAIRWISE:%d\n",sM.pCSS[3]);
           // printf("ASS COUNT:%02x-%02x\n",sM.aSC[0],sM.aSC[1]);
           // printf("ASS:%d\n",sM.aSS[3]);
            //ID:221 WPA-1
           // printf("MULTI:%d\n",sM.mCSS[3]);
           // printf("UNI COUNT:%02x-%02x\n",sM.uCSC);
           // printf("UNI:%d\n",sM.uCSS[3]);
           // printf("AKMS COUNT:%02x-%02x\n",sM.aKMC[0],sM.aKMC[1]);
           // printf("AKMS:%d\n",sM.aKMS[3]);
          //  printf("##############################\n");

          // printf("--------------------------------\n");
           //---------------compare listed datas <-> captured datas
           exPkt.apAuth = sF.auth;
           exPkt.apCipher = sF.groupCipher;
           exPkt.apEnc = sF.enc;
           int cmpFlag = 0;
           int macCmpFlag = 0;
           listload::bw_list::iterator it;

            for(it = listMan2.WhiteList.begin();it !=listMan2.WhiteList.end();it++){
               //printf("view func first %d\n",it->first);
               bwDatas = (listload::bwList)it->second;
               macCmpFlag = memcmp(&(bwDatas.apMac),&(mF->addr3),6);
               if(macCmpFlag == 0){

               //printf("view func datas %d %02x %02x %02x %02x %02x %02x\n",bwDatas.apCipher,bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
                   listSF.auth = bwDatas.apAuth;
                   listSF.enc = bwDatas.apEnc;
                   listSF.groupCipher = bwDatas.apCipher;
                   listSF.pairwiseCipher = bwDatas.apCipher;
                   cmpFlag = memcmp(&listSF,&sF,sizeof(SecurityFlag));
                   if(cmpFlag == 0){
                       printf("LISTED AP RULE!(WHITE)\n");
                       WHTFlag = true;
                       break;
                       //passpkt
                   }
               }
           }

           cmpFlag = 0;
           macCmpFlag = 0;
           if(WHTFlag == false){
               printf("NOT LISTED AP RULE(WHITE)\n");
                //cmpFlag = 0;
                //uint8_t cmpArray[6];
                listload::bw_list::iterator it1;


                //blk list!
                for(it1 = listMan2.BlackList.begin();it1 !=listMan2.BlackList.end();it1++){
                    bwDatas = (listload::bwList)it1->second;
                    //printf("cmp with %02x %02x %02x %02x %02x %02x\n",bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
                    //printf("checking blk ap rule\n");
                    macCmpFlag = memcmp(&(bwDatas.apMac),&(mF->addr3),6);
                    if(macCmpFlag == 0){

                        //printf("view func datas %d %02x %02x %02x %02x %02x %02x\n",bwDatas.apCipher,bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
                        listSF.auth = bwDatas.apAuth;
                        listSF.enc = bwDatas.apEnc;
                        listSF.groupCipher = bwDatas.apCipher;
                        listSF.pairwiseCipher = bwDatas.apCipher;
                        cmpFlag = memcmp(&listSF,&sF,sizeof(SecurityFlag));
                        if(cmpFlag == 0){
                                printf("LISTED AP RULE!(BLACK)\n");
                                BLKFlag = true;
                                break;
                                //pass pkt
                        }
                    }


              }

          }
          printf("NOT LISTED AP RULE(BLACK) \n");
          if(WHTFlag == false && BLKFlag == false){
                    storFlag = true;
                    char tempbuf[250] = {0,};
                    sprintf(tempbuf,"%s MISCONFIGURE AP",atkType);
                    sprintf(atkType,"%s",tempbuf);
                    //sprintf(blkBuff,"INSERT INTO TEST_BB (ap_mac,channel,block_stat)  VALUES ('%02x%02x%02x%02x%02x%02x',%d,%d)",exPkt.apMac[0],exPkt.apMac[1],exPkt.apMac[2],exPkt.apMac[3],exPkt.apMac[4],exPkt.apMac[5],exPkt.channel,exPkt.blockStat);
                    printf("\ndisordered!(AP RULE)\n");
                    //start function(structure write and throw map,db)

          }

          //pkt data extract here
           //*********************Initialization*******************
           memset(rH,0,sizeof(struct RadiotapHeader));
           memset(rF,0,sizeof(struct RadiotapHeaderFlag));
           memset(mF,0,sizeof(struct ManagementFrame));
           memset(fC,0,sizeof(struct FrameCtrl));
           memset(oF,0,sizeof(struct OptionField));
           memset(rsn,0,sizeof(struct Rsn));
           memset(vS,0,sizeof(struct VendorSpecific));
           //memset(sM,0,sizeof(struct SecurityMethod));
           //memset(sF,0,sizeof(struct SecurityFlag));
          // memset(koT,0,sizeof(struct KindOfType));
           //printf("done!\n\n");
           return 0;

}


void usrfunc::test_viewFunc(listload& listMan2){

   // lLoad = listMan2;
    //listload::blk_list test = blkColl;
    listload::bw_list::iterator it;

    for(it = listMan2.BlackList.begin();it !=listMan2.BlackList.end();it++){
        //printf("view func first %d\n",it->first);
        bwDatas = (listload::bwList)it->second;
        //printf("view func datas %d %02x %02x %02x %02x %02x %02x\n",bwDatas.apCipher,bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);

    }


}


void usrfunc::macCmp(listload& listMan2){
      WHTFlag = false; //true in whitelisted packet
      BLKFlag = false; //true in blacklisted packet
      RadiotapHeader *RH = (RadiotapHeader*)(pktPoint);
      int length = RH->length;
      ManagementFrame *MF = (ManagementFrame*)(pktPoint+length);

     // int type = MF->frameCtrl.type;
     // int subtype = MF->frameCtrl.subType;

     // int ToDs = MF->frameCtrl.toDs;
      //int FromDs = MF->frameCtrl.fromDs;


      //if(type == 0 && subtype ==0) // Association Request Frame
      //if((ToDs == 0 && FromDs == 1) || (ToDs == 1 && FromDs == 0))
    //  {
          //printf("====================================================\n");
         /* if(ToDs == 0 && FromDs == 1)
          {
              printf("From AP\n");
          }
          else
          {
              printf("To AP\n");
          }*/

          //printf("Sequnce  : %d\n", (MF->seq));

          //printMac(1);    //DA
          //printMac(2);    //SA
          //printMac(3);    //BSS ID
          int cmpFlag = 0;
          //int macCmpFlag = 0;
          //uint8_t cmpArray[6];
          listload::bw_list::iterator it;
          printf("-------------------------------------------------\n");
          printf("AP MAC CHECK\n\n");


          //wht list!
          for(it = listMan2.WhiteList.begin();it !=listMan2.WhiteList.end();it++){
              //printf("view func first %d\n",it->first);
              bwDatas = (listload::bwList)it->second;
              printf("pkt compare with %02x %02x %02x %02x %02x %02x\n",bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
              printf("current pack bssid is %02x %02x %02x %02x %02x %02x\n",MF->addr3[0],MF->addr3[1],MF->addr3[2],MF->addr3[3],MF->addr3[4],MF->addr3[5]);
              cmpFlag = memcmp(&(bwDatas.apMac),&(MF->addr3),6);
              if(cmpFlag == 0){
                  printf("LISTED AP MAC!(WHITE)\n");
                  WHTFlag = true;
                  break;
                  //start function(structure write and throw map,db)
              }

          }

          if(WHTFlag == false){
              printf("NOT LISTED AP MAC(WHITE)\n");
              cmpFlag = 0;
              //uint8_t cmpArray[6];
              listload::bw_list::iterator it1;


              //blk list!
              for(it1 = listMan2.BlackList.begin();it1 !=listMan2.BlackList.end();it1++){
                    //printf("view func first %d\n",it->first);
                    bwDatas = (listload::bwList)it1->second;
                    printf("cmp with %02x %02x %02x %02x %02x %02x\n",bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);

                    cmpFlag = memcmp(&(bwDatas.apMac),&(MF->addr3),6);
                    if(cmpFlag == 0){
                        printf("LISTED AP MAC!(BLACK)\n");
                        BLKFlag = true;
                        break;
                        //already enrolled packet
                                //start function(structure write and throw map,db)
                     }

               }

          }
          if(WHTFlag == false && BLKFlag == false){
                   printf("\ndisordered!(AP MAC)\n\n");
                   storFlag = true;
                   char tempbuf[250] = {0,};
                   sprintf(tempbuf,"%s UNDEFINED AP MAC",atkType);
                   sprintf(atkType,"%s",tempbuf);
                   //start function(structure write and throw map,db)

               }


          /*
          for(int i=0 ; i<6; i++)
          {
              int n = memcmp((char*)&MF->addr2[i], (char*)&MF->addr3[i], 6);
              if(n != 0)
              {
                  printf("different\n");
                  break;
              }
              if(i==5)
              {
                  printf("same\n");
              }
          }

         */
 }



//-----------------------------------------------------------------------------------------------------------------------
void usrfunc::adhocFunc(listload& listMan2)
{
    WHTFlag = false; //true in whitelisted packet
    BLKFlag = false; //true in blacklisted packet
    //WHTFlag = false; //true in whitelisted packet
    //BLKFlag = false; //true in blacklisted packet
    Radiotap_Header *RD;
    RD = (Radiotap_Header *)pktPoint;
    Manage *MN;
    MN = (Manage *)((u_char *)pktPoint+(RD->Header_Length));
    //u_int16_t type1 = ntohs(MN->Duration);
    //u_int16_t type2 = ntohs(MN->Sequence);
    //u_int8_t frame_type = MN->Frame_control.Type;
    u_int8_t IBSS_Status = MN->Wireless_LAN.Capavility.IBSS;
    exPkt.adHocStat = IBSS_Status;
    //listMan2.bwStruct.adHocStat = IBSS_Status;

/*
    if (frame_type == 0){
        printf("-------------------------------------------------\n");
        printf("Managemenet Frame\n");
        printf("FramControl : %04x\n", MN->Frame_control);
        printf("frame type : %02x\n", frame_type);
        printf("Duration/ID Field : %04x\n",type1);
        printf("DA : %02x-%02x-%02x-%02x-%02x-%02x\n", MN->des[0],MN->des[1],MN->des[2],MN->des[3],MN->des[4],MN->des[5]);
        printf("SA : %02x-%02x-%02x-%02x-%02x-%02x\n", MN->src[0],MN->src[1],MN->src[2],MN->src[3],MN->src[4],MN->src[5]);
        printf("BSS ID : %02x-%02x-%02x-%02x-%02x-%02x\n", MN->BSS[0],MN->BSS[1],MN->BSS[2],MN->BSS[3],MN->BSS[4],MN->BSS[5]);
        printf("Sequence : %04x\n", type2);
        printf("Capability : %04x\n", MN->Wireless_LAN.Capavility);
        printf("IBSS_satus : %01x\n",IBSS_Status);
    }
*/
  //  if (IBSS_Status == 1)
    // printf("\nAD-HOC Network\n");
    int cmpFlag = 0;
    int macCmpFlag = 0;
    //uint8_t cmpArray[6];
    listload::bw_list::iterator it;

    printf("-------------------------------------------------\n");
      //wht list!
    printf("CHECK IBSS\n\n");
     for(it = listMan2.WhiteList.begin();it !=listMan2.WhiteList.end();it++){
        //printf("view func first %d\n",it->first);
        bwDatas = (listload::bwList)it->second;
        macCmpFlag = memcmp(&(bwDatas.apMac),&(MN->BSS),6);
        if(macCmpFlag == 0){
            printf("cmp ibss with %d\n",bwDatas.adHocStat);

            cmpFlag = memcmp(&(bwDatas.adHocStat),&(IBSS_Status),1);
            if(cmpFlag == 0){
                printf("LISTED IBSS!(WHITE)\n");
                WHTFlag = true;
                break;
                //alreay have white list OK.
            }
        }
    }

    cmpFlag = 0;
    macCmpFlag = 0;
    if(WHTFlag == false){
        printf("NOT LISTED IBSS(WHITE) \n");
        cmpFlag = 0;
        //uint8_t cmpArray[6];
        listload::bw_list::iterator it1;


                    //blk list!
        for(it1 = listMan2.BlackList.begin();it1 !=listMan2.BlackList.end();it1++){
              //printf("view func first %d\n",it->first);
              bwDatas = (listload::bwList)it1->second;
              //printf("cmp with %02x %02x %02x %02x %02x %02x\n",bwDatas.apMac[0],bwDatas.apMac[1],bwDatas.apMac[2],bwDatas.apMac[3],bwDatas.apMac[4],bwDatas.apMac[5]);
              //printf("check blk ibss\n");
              macCmpFlag = memcmp(&(bwDatas.apMac),&(MN->BSS),6);
              if(macCmpFlag == 0){
                  printf("cmp ibss with %d\n",bwDatas.adHocStat);

                  cmpFlag = memcmp(&(bwDatas.adHocStat),&(IBSS_Status),1);
                  if(cmpFlag == 0){
                      printf("LISTED IBSS\n");
                      BLKFlag = true;
                      break;
                      //alreay have black list OK.
                  }
              }

         }

      }
      printf("NOT LISTED IBSS(BLACK) \n");
      if(WHTFlag == false && BLKFlag == false){
          printf("\ndisordered!(ad_hoc)\n\n");
          storFlag = true;
          char tempbuf[250] = {0,};
          sprintf(tempbuf,"%s AD HOC",atkType);
          sprintf(atkType,"%s",tempbuf);
          //start function(structure write and throw map,db)

      }



}



void usrfunc::retMacAdr(void)
{
    switch(this->frameCtrl->toDs){
        case 0:
        {
            if(this->frameCtrl->fromDs == 0){//00
                memcpy(this->APMac,this->mgmtFrame->addr3,6);
                memcpy(this->cliMac,this->mgmtFrame->addr1,6);
            }else if(this->frameCtrl->fromDs == 1){
                memcpy(this->APMac,this->mgmtFrame->addr2,6);
                memcpy(this->cliMac,this->mgmtFrame->addr1,6);

            }

        }
        break;
        case 1:
        {
            if(this->frameCtrl->fromDs == 0){//00
                memcpy(this->APMac,this->mgmtFrame->addr1,6);
                memcpy(this->cliMac,this->mgmtFrame->addr3,6);
            }else if(this->frameCtrl->fromDs == 1){
                //memcpy(this->APMac,this->mgmtFrame->addr3,6);
                //memcpy(this->cliMac,this->mgmtFrame->addr1,6);
                printf("11\n");

            }
        }
        break;
    }
    }

void usrfunc::getCurPktData(listload& listMan2){
    radioGetData();//channel
    exPkt.blockStat = 1;
    exPkt.macType = 0;//beaconFrame


    memcpy(exPkt.apMac,mgmtFrame->addr3,6);
    memset(exPkt.stMac,0,6);//beaconFrame
    memset(atkType,0,sizeof(atkType));
    WHTFlag = false; //true in whitelisted packet
    BLKFlag = false;
    storFlag = false;

    /*

        int apAuth;
        int apCipher;
        int apEnc;

        uint8_t adHocStat;

        uint8_t ssid[50];

    */


}
void usrfunc::radioGetData(void){
    //printf("test1\n\n\n\n");
    int pflgLth = 0;
    //u_long checkNum = 0;
    bool pflgChk = false;
    for(u_long i=0; i<3;i++){
        pflgChk = RTHeader->rth_present_flg.pflg1.test(i);
        //std::cout << pflgChk <<std::endl;
        if(pflgChk == true){
            pflgLth += PFrame.pflg_allign[i];
            //printf("current pFlg %d\n",pflgLth);
        }

    }
    //setting channel
    //uint16_t channel12;
    //printf("sizeof rthear %d\n",sizeof(RTHeader));
   // memcpy(&exPkt.channel,(pktPoint+RTHEADERSIZE+pflgLth),2);
    uint16_t HzChan = 0;
    memcpy(&HzChan,(pktPoint+RTHEADERSIZE+pflgLth),2);
    printf("memcpy channel! %d\n",HzChan);
    exPkt.channel = hzToCnl(HzChan);
    //printf("show channel %02x %02x\n",channel12[0],channel12[1]);
    //channel12 = ntohs(channel12);
    //printf("show channel %d\n",channel12);


}

void usrfunc::inputCurPkt(listload& listMan2,dbmanage& wipsDB2){
    printf("expkt channel %d\n",exPkt.channel);
    char blkBuff[255];
    char logBuff[255];
    //exPkt;
    printf("INSERT INTO wips_black_blacklist (ap_mac,channel,blockstat) VALUES ('%02x%02x%02x%02x%02x%02x',%d,%d)\n",exPkt.apMac[0],exPkt.apMac[1],exPkt.apMac[2],exPkt.apMac[3],exPkt.apMac[4],exPkt.apMac[5],exPkt.channel,exPkt.blockStat);
    sprintf(blkBuff,"INSERT INTO wips_black_blacklist (ap_mac,channel,block_stat,ap_auth,ap_cipher,ap_enc,mac_type,ad_hoc_stat,ap_ssid) VALUES ('%02x%02x%02x%02x%02x%02x',%d,%d,%d,%d,%d,%d,%d,'%s')",exPkt.apMac[0],exPkt.apMac[1],exPkt.apMac[2],exPkt.apMac[3],exPkt.apMac[4],exPkt.apMac[5],exPkt.channel,exPkt.blockStat,exPkt.apAuth,exPkt.apCipher,exPkt.apEnc,exPkt.macType,exPkt.adHocStat,exPkt.ssid);
    printf("send blk!! %s\n",blkBuff);
    wipsDB2.dbQuery(blkBuff);
    sprintf(logBuff,"INSERT INTO wips_home_blocklog (mac,atk_type,block_stat)  VALUES ('%02x%02x%02x%02x%02x%02x','%s',%d)",exPkt.apMac[0],exPkt.apMac[1],exPkt.apMac[2],exPkt.apMac[3],exPkt.apMac[4],exPkt.apMac[5],atkType,exPkt.blockStat);
    printf("send log!! %s\n",logBuff);
    wipsDB2.dbQuery(logBuff);
    //input data in map
    listMan2.blkCnt +=1;
    memset(&(listMan2.bwStruct),0,sizeof(listMan2.bwStruct));
    //memcpy(&(listMan2.bwStruct),&exPkt,sizeof(exPkt));
    listMan2.bwStruct.apAuth = exPkt.apAuth;
    listMan2.bwStruct.channel = exPkt.channel;
    listMan2.bwStruct.blockStat = exPkt.blockStat;
    listMan2.bwStruct.apCipher = exPkt.apCipher;
    listMan2.bwStruct.apEnc = exPkt.apEnc;
    listMan2.bwStruct.macType = exPkt.macType;
    listMan2.bwStruct.adHocStat = exPkt.adHocStat;
    memcpy(&(listMan2.bwStruct.apMac[0]),&(exPkt.apMac[0]),6);
    memcpy(&(listMan2.bwStruct.stMac[0]),&(exPkt.stMac[0]),6);
    memcpy(&(listMan2.bwStruct.ssid),&(exPkt.ssid),32);

    listMan2.BlackList.insert(std::make_pair(listMan2.blkCnt,listMan2.bwStruct));

    //change query
}
int usrfunc::hzToCnl(uint16_t recvhz){
    switch(recvhz) {
        case 2412:{
            return 1;
        }
        case 2417:{
            return 2;
        }
        case 2422:{
            return 3;
        }
        case 2427:{
            return 4;
        }
        case 2432:{
            return 5;
        }
        case 2437:{
            return 6;
        }
        case 2442:{
            return 7;
        }
        case 2447:{
            return 8;
        }
        case 2452:{
            return 9;
        }
        case 2457:{
            return 10;
        }
        case 2462:{
            return 11;
        }
        case 2467:{
            return 12;
        }
        case 2472:{
            return 13;
        }
        case 2482:{
            return 14;
        }
        default :
            break;


    }

}
