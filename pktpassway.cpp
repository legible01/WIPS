#include <iostream>

//#include <ctypes>

#include "pktpassway.h"
#include "listload.h"
//#include "dbmanage.h"
#include "devsearch.h"
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

char *correct_dev(int argu_count,char *argu_vector);


int main(int argc, char *argv[])
{

    dbmanage wipsDB;


    //devCheck
    char* dev = correct_dev(argc,argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pktDescrpt = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 0, errbuf);
    if(pktDescrpt == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }

    //database connect


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

char *correct_dev(int argCnt,char *argVector)
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
