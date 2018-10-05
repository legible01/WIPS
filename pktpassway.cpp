#include "pktpassway.h"


using namespace std;

//char pktpassway::*correct_dev(int argu_count,char *argu_vector);


int pktPassWay::main(void)
{
    //database connect
    dbmanage wipsDB;
    listLoad listMan;

    //query(dbMacField,query)
    int dBMacFld = 0;
    int stat =  listMan.initTbl(wipsDB.dbQuery("SELECT * FROM wips_black_blacklist"),dBMacFld);
    //initTbl send wipsdb. query table
    printf("thus");

    //devCheck
    //char* dev = correct_dev(argc,argv[1]);
    char *dev = "wlan1";
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
    while(true)
    {

        loopStat = pcap_next_ex(pktDescrpt, &pktHdr, &pktData);
        //(void)pktHdr;//useless
        //pcap_stats(packeDescrpt,&stat);//useless

        switch(loopStat)
        {
            case 1:
            //packet filtering
            //int function(argvs)
            //checkflag = func1(pktDescrpt);
                pktFilter((uint8_t*)pktData);
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



void pktPassWay::pktFilter(uint8_t *pktData)
{
    //uint8_t*
    usrfunc usrFunc(pktData);
    //make reference
    //printf("")
    switch(usrFunc.frameCtrl->type){

        case(0):
            //D memList.getPktInfo(pktData);

            switch(usrFunc.frameCtrl->subType){
                case(8):
                    usrFunc.fakeAp();
                    //memList.getPktInfo(pktData);
                    break;
                case(10):
                   //D memList.getPktInfo(pktData);
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
