#include "usrfunc.h"

usrfunc::usrfunc(uint8_t *packet)
{
    this->pktPoint = packet;
    this->RTHeader = (packframes::rth*)packet;
    this->frameCtrl = (packframes::FC*)((uint8_t*)(packet+RTHeader->rth_length));
    this->mgmtFrame = (packframes::ManagementFrame*)((uint8_t*)(packet+RTHeader->rth_length));
}

void usrfunc::fakeAp(listload& listMan2)
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

    uint8_t *data = this->pktPoint;
    struct RadiotapHeader *rH;
    struct RadiotapHeaderFlag *rF;
    struct ManagementFrame *mF;
    struct FrameCtrl *fC;
    struct OptionField *oF;
    struct Rsn *rsn;
    struct VendorSpecific *vS;
    struct SecurityMethod sM;
    struct SecurityFlag sF;
    struct SecurityFlag listSF;
    struct AkmSuiteSelector *aS;
    struct PairwiseCipherSuiteSelector *pS;


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
           printf("NOT LISTED AP RULE(WHITE)\n");
           cmpFlag = 0;
           macCmpFlag = 0;
           if(WHTFlag == false){
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
                    printf("\ndisordered!(AP RULE)\n");
                    //start function(structure write and throw map,db)

          }


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

              cmpFlag = memcmp(&(bwDatas.apMac),&(MF->addr3),6);
              if(cmpFlag == 0){
                  printf("LISTED AP MAC!(WHITE)\n");
                  WHTFlag = true;
                  break;
                  //start function(structure write and throw map,db)
              }

          }
          printf("NOT LISTED AP MAC(WHITE)\n");
          if(WHTFlag == false){
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
    Radiotap_Header *RD;
    RD = (Radiotap_Header *)pktPoint;
    Manage *MN;
    MN = (Manage *)((u_char *)pktPoint+(RD->Header_Length));
    //u_int16_t type1 = ntohs(MN->Duration);
    //u_int16_t type2 = ntohs(MN->Sequence);
    //u_int8_t frame_type = MN->Frame_control.Type;
    u_int8_t IBSS_Status = MN->Wireless_LAN.Capavility.IBSS;

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
    printf("NOT LISTED IBSS(WHITE) \n");
    cmpFlag = 0;
    macCmpFlag = 0;
    if(WHTFlag == false){
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
          //start function(structure write and throw map,db)

      }



}



