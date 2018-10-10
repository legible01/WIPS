#include "listload.h"
#include <typeinfo>
#include <cstring>



listload::listload()
{
//make map for dev list
//accessList
//getDevList();
//blackList
//whitelist


}

//basically macField = 0
int listload:: initlist(MYSQL_RES* lRes,int lFlag)
{

    bwStruct={0};
    int fCnt = mysql_num_fields(lRes);
    int rowNum = 0;
    while((row = mysql_fetch_row(lRes)))
    {
        rowNum = (int)strtol(row[0],NULL,10);
        printf("num check1 is %d\n",rowNum);
        convMac(0,row[1]);
        bwStruct.channel = (int)strtol(row[2],NULL,10);
        bwStruct.blockStat = (int)strtol(row[3],NULL,10);
        convMac(1,row[4]);
        bwStruct.apAuth = (int)strtol(row[5],NULL,10);
        bwStruct.apCipher = (int)strtol(row[6],NULL,10);
        bwStruct.apEnc = (int)strtol(row[7],NULL,10);
        bwStruct.macType = (int)strtol(row[8],NULL,10);
        printf("st test %02x %02x %02x %02x %02x %02x\n",bwStruct.apMac[0],bwStruct.apMac[1],bwStruct.apMac[2],bwStruct.apMac[3],bwStruct.apMac[4],bwStruct.apMac[5]);
        printf("\n");
        if(lFlag == 10){
            BlackList.insert(std::make_pair(rowNum,bwStruct));
        }else if(lFlag == 11){
            WhiteList.insert(std::make_pair(rowNum,bwStruct));
        }

    }
    bw_list::iterator it;
    for(it = BlackList.begin();it !=BlackList.end();it++){
        printf("first %d\n",it->first);


    }
    //printf("thie end\n\n");
    return 0;
}

int listload:: initwht(MYSQL_RES* lRes)
{

    bwStruct={0};
    int fCnt = mysql_num_fields(lRes);
    int rowNum = 0;
    while((row = mysql_fetch_row(lRes)))
    {
        rowNum = (int)strtol(row[0],NULL,10);
        printf("num check1 is %d\n",rowNum);
        convMac(0,row[1]);
        bwStruct.channel = (int)strtol(row[2],NULL,10);
        bwStruct.blockStat = (int)strtol(row[3],NULL,10);
        convMac(1,row[4]);
        bwStruct.apAuth = (int)strtol(row[5],NULL,10);
        bwStruct.apCipher = (int)strtol(row[6],NULL,10);
        bwStruct.apEnc = (int)strtol(row[7],NULL,10);
        bwStruct.macType = (int)strtol(row[8],NULL,10);
        printf("st test %02x %02x %02x %02x %02x %02x\n",bwStruct.apMac[0],bwStruct.apMac[1],bwStruct.apMac[2],bwStruct.apMac[3],bwStruct.apMac[4],bwStruct.apMac[5]);
        printf("\n");

        BlackList.insert(std::make_pair(rowNum,bwStruct));


    }
    bw_list::iterator it;
    for(it = BlackList.begin();it !=BlackList.end();it++){
        printf("first %d\n",it->first);


    }
    //printf("thie end\n\n");
    return 0;
}

void listload:: convMac(int macFlag,std::string recvMac){
    //std::vector<char> cMac(recvMac.c_str(), recvMac.c_str() + recvMac.size() + 1);
    //char cMac[12] = (char)recvMac[];
    //printf("%s\n",cMac);
    //char const *test1 = recvMac.c_str();
    //char* test1;
    //std::strcpy(test1, recvMac.c_str());
    //char hexbyte[3] = {0,};
    //int octets[sizeof(recvMac) / 2];
    int arrCnt = 0;
    if(recvMac.length() == 12)
    {
        if(macFlag == 0)//apMac
        {
            for(int ex = 0;ex<12;ex+=2 ){
                std::string tempstr = recvMac.substr(ex,2);
                uint8_t num1 = (uint8_t)strtol(tempstr.c_str(),NULL,16);
                arrCnt = ex/2;
                bwStruct.apMac[arrCnt] = num1;
                //printf("ok %02x\n",bwStruct.apMac[arrCnt]);
                }
            //char *te1 = "90";
           // printf("test %d\n",bwStruct.apMac[0]);
            //int test3 = std::atoi("");

            //printf("test2sdf %02x\n\n",num1);

        }else if(macFlag == 1)//stationMac
        {
            for(int ex = 0;ex<12;ex+=2 ){
                std::string tempstr = recvMac.substr(ex,2);
                uint8_t num1 = (uint8_t)strtol(tempstr.c_str(),NULL,16);
                arrCnt = ex/2;
                bwStruct.stMac[arrCnt] = num1;
                //printf("ok %02x\n",bwStruct.stMac[arrCnt]);
                }

        }
    }//else{//not 12 length mac then
        //uint8_t num1 = (uint8_t)strtol(recvMac.c_str(),NULL,16);
   // }

}

void listload:: getPktInfo(uint8_t* pktData){
   //uint8_t* rth_data = pktData+RTHLENGTH;
   uint8_t* rssAdr = pktData+RTHLENGTH;
   uint8_t* channelAdr = pktData+RTHLENGTH;

   rthFrame =  (packframes::rth *)pktData;
   int d_form=4;
   int padding=0;
   //D printf("\nchannel cur adr = %p\n",channelAdr);
   for(int temp=0;temp<29;temp++){
       if(rthFrame->rth_present_flg.pflg1[temp]== false){
           continue;
       }
       else if(rthFrame->rth_present_flg.pflg1[temp]==true){
           while((d_form % PFrame.pflg_allign[temp])!=0){

               d_form+=1;
               padding+=1;
           }
           if(temp<3){
               //D printf("\nchan_tmp = %d, pading = %d size=%d\n",temp,padding,PFrame.pflg_size[temp]);
               channelAdr=channelAdr+padding+PFrame.pflg_size[temp];
               //D printf("\nchannel cur adr = %p\n",channelAdr);
           }

           d_form= d_form+PFrame.pflg_size[temp];
           padding=0;
           continue;
       }

   }
   rssAdr += (d_form-4);
   infoForm.channel = ntohs((uint16_t)*channelAdr);
   infoForm.rss = (char)*rssAdr;



   //D printf("\n\n\n rth_data = %p \n rthdata is %02x\n",channelAdr,channelAdr[0]);
   //D printf("\ncur rss_position = %p\n data is %02x %02x\n",rssAdr,rssAdr[0],rssAdr[1]);

//-------------------rth_data_abstract_end--------------------

   //printf("\nsize of struct = %d\n",sizeof();

   //while(pflg_index){
       //for(int temp;temp<4;temp++){
            //&cmp_v
       //}
    //printf("\ntt\n");

  // }
   /* uint8_t test1 = (rthFrame->rth_present_flg.pflg1.TSFT);
   uint8_t test2 = (rthFrame->rth_present_flg.pflg1.Flags);
   uint8_t test3 = (rthFrame->rth_present_flg.pflg1.Rate);
   uint8_t test4 = (rthFrame->rth_present_flg.pflg1.Channel);
   uint8_t test5 = (rthFrame->rth_present_flg.pflg1.dbm_antenna_signal);
   uint8_t test6 = (rthFrame->rth_present_flg.pflg1.RX_flags);
   uint8_t test7 = (rthFrame->rth_present_flg.pflg1.radiotap_NS_next);
   uint8_t test8 = (rthFrame->rth_present_flg.pflg1.Ext);
   uint8_t test9 = (rthFrame->rth_present_flg.pflg2.dbm_antenna_signal);
   printf("\ntest pflg1 = %02x \n fhss = %02x %02x %02x %02x %02x %02x %02x %02x \n",test1,test2,test3,test4,test5,test6,test7,test8,test9);
   */
   //enum packframes::RTH_pflg presentFlag;
   // =

   /*while(presentFlag != 31){

       if(rthFrame->rth_present_flg.pflg1[presentFlag]|rthFrame->rth_present_flg.pflg2)

       switch(presentFlag)
       {
            case(packframes::RTH_TSFT):
                printf("1");
                continue;
            default:
                printf("end");
       }
   }*/
   /*
   presentFlag = packframes::RTH_TSFT;
   printf("\n enum data = %d\n",presentFlag);
   presentFlag = packframes::RTH_FLAGS;
   printf("\n enum data2 = %d\n",presentFlag);
   */
    //while()
   //switch
  // rthFrame->rth_length
    //switch()


}
listload::bw_list& listload::rtnBlkMap(){

    return this->BlackList;
}
