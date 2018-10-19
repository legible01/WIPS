#include "pktpassway.h"
#define BLACKLISTFLAG 10
#define WHITELISTFLAG 11


using namespace std;

//char pktpassway::*correct_dev(int argu_count,char *argu_vector);


int pktPassWay::main(void)
{
    //database connect
    dbmanage wipsDB;
    listload listMan;

    //query(dbMacField,query)

    printf("BLACKLIST ENROLL\n");
    int stat =  listMan.initlist(wipsDB.dbQuery("SELECT * FROM wips_black_blacklist"),BLACKLISTFLAG);
    printf("WHITELIST ENROLL\n");
    int stat1 =  listMan.initlist(wipsDB.dbQuery("SELECT * FROM wips_white_whitelist"),WHITELISTFLAG);
    //initTbl send wipsdb. query table
    // debug printf("thus\n");

    //devCheck
    //char* dev = correct_dev(argc,argv[1]);
    char *dev = "wlan3";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pktDescrpt = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 0, errbuf);
    if(pktDescrpt == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }

    //pkt recv
    int loopStat;
    struct pcap_pkthdr *pktHdr;
    const u_char *pktData;
    printf("packets waiting...\n");
    while(true)
    {

        loopStat = pcap_next_ex(pktDescrpt, &pktHdr, &pktData);
        //(void)pktHdr;//useless
        //pcap_stats(packeDescrpt,&stat);//useless

        switch(loopStat)
        {
        case 1:
        {
                pktFilter((uint8_t*)pktData,listMan, wipsDB);
                break;
        }
            case 0:
                continue;//timeout check
            case -1:
                pcap_perror(pktDescrpt,"Packet data read error");
                exit(1);
            case -2:
                pcap_perror(pktDescrpt,"Packet data read error");
                exit(1);
        }
    }
    printf("end while\n");
    return 0;
}

char* pktPassWay::correct_dev(int argCnt,char *argVector)
{
    if (argCnt != 2){
        printf("use this form to use program\nProgramName DeviceName\n");
        printf("available dev Lists\n");
        devsearch t1;
        t1.GetDevList();

        exit(1);
    }
    printf("Device : %s\n", argVector);
    return argVector;
}



void pktPassWay::pktFilter(uint8_t *pktData,listload& listMan1,dbmanage& wipsDB1)
{
    int debugCnt = 0;
    //uint8_t*
    usrfunc usrFunc(pktData);
    //printf("===========================PACKET CAPTURE===============================\n\n");
    memset(&(usrFunc.exPkt),0,sizeof(usrFunc.exPkt));
    //usrFunc.test_viewFunc(listMan1);
    //make reference
    //printf("")
    switch(usrFunc.frameCtrl->type){
        case(0):{
            //D memList.getPktInfo(pktData);

            switch(usrFunc.frameCtrl->subType){

                case(8):
                {
                    usrFunc.getCurPktData(listMan1);
                    if(usrFunc.doFlag == true){
                        break;
                    }
                    printf("===========================PACKET CAPTURE===============================\n\n");
                    int aa;
                    usrFunc.macCmp(listMan1);
                    usrFunc.adhocFunc(listMan1);


                    usrFunc.fakeAp(listMan1);
                    aa = usrFunc.misconfigureAP(listMan1);
                    //usrFunc.test_viewFunc(listMan1);

                    //printf("misconf\n");




                    //memList.getPktInfo(pktData);
                    if(usrFunc.storFlag == true){
                        usrFunc.inputCurPkt(listMan1,wipsDB1);
                        usrFunc.storFlag = false;
                        memset(usrFunc.atkType,0,sizeof(usrFunc.atkType));

                        }
                    debugCnt+=1;
                    if(debugCnt == 10)
                        system("PAUSE");
                    break;
                    }
                case(10):{
                   //D memList.getPktInfo(pktData);
                    break;

                }
                default:
                    break;
            }
        break;
        }
        case(1):
        //type is 1
            printf("\n");
            break;
        case(2):
            printf("\n");
            break;
        case(3):
            printf("\n");
            break;




    }



}
