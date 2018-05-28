#include "listload.h"
#include <typeinfo>
#include <cstring>



listLoad::listLoad()
{
//make map for dev list
//accessList
//getDevList();
//blackList
//whitelist


}
//basically macField = 0
int listLoad:: initTbl(MYSQL_RES* lRes,int macField = -1)
{

    int fCnt = mysql_num_fields(lRes);
    while((row = mysql_fetch_row(lRes)))
    {
        for(int cnt = 0; cnt<fCnt; cnt++)
        {
            if(cnt == macField)
            {
               char* intMac = row[0];
               //rintf("tec=%s",tec);
               tempMac = intMac;//MAC overload



            }
            printf("%12s",this->row[cnt]);
            //std::cout << typeid(*row[1]).name() <<'\n';//debug
        }
            printf("\n");


    }
    return 0;
}


void listLoad:: getPktInfo(uint8_t* pktData){
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

