#include <iostream>
#include <ctypes>

#include "pktpassway.h"
#include "listload.h"

using namespace std;

char *correct_dev(int argu_count,char *argu_vector);
void packet_control(pcap_t * packet_descriptor,pcap_stat& stat);

int main(int argc, char *argv[])
{
    listLoad tt;
    tt.getDevList();
    

    char *dev =correct_dev(argc,argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
    int flags = PROMISCUOUS;

    pcap_t *packet_descriptor = pcap_open_live(dev, BUFSIZ, flags, 300, errbuf);
    struct pcap_stat stat;
    if(packet_descriptor == NULL) {
        printf("%s\n",errbuf);
        exit(1);
    }else{
        packet_control(packet_descriptor,stat);

    }


    return 0;
}

char *correct_dev(int argu_count,char *argu_vector)
{
    if (argu_count != 2){
        printf("use this form to use program\nProgramName DeviceName\n");
        exit(1);
    }
    printf("Device : %s\n", argu_vector);
    return argu_vector;
}

void packet_control(pcap_t * packet_descriptor,pcap_stat& stat)
{
    while((loopstatus = pcap_next_ex(packet_descriptor, &pkt_hdr, &pkt_data)) >= 0){//pkt_data 's adress
       (void)pkt_hdr;//useless
       pcap_stats(packet_descriptor,&stat);


        if(loopstatus == 0)
            continue;//timeout check
        if(loopstatus == -1 || loopstatus == -2)
            pcap_perror(packet_descriptor,"Packet data read error");
}
