#include "deauth.h"


deauth::deauth()
{

}
void deauth::main_deauth(char * devName = "wlan0")
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * packHandle = pcap_open_live(devName, BUFSIZ, 1, 300, errbuf);

    //deAuth_pkt*[]; packet uint8_t array

    //pcap_sendpacket(packHandle,packet_pointer,packet_size)
}

void deauth::send_deauth(uint8_t*addr1,uint8_t*addr2,int objPkt)
{
    create_pack(addr1, addr2, objPkt);
}
void deauth::create_pack(uint8_t* client, uint8_t*ap,int objPkt)
{
    dpack.mgmt.fC.version = 0;
    dpack.mgmt.fC.type = 0;
    dpack.mgmt.fC.subtype = 12;
    dpack.mgmt.fC.flags = 0;
    dpack.mgmt.duration = 0;
    if (objPkt == Client){
        std::memcpy(dpack.mgmt.dstAdr,client,6);
        std::memcpy(dpack.mgmt.srcAdr,ap,6);
    }else{
        std::memcpy(dpack.mgmt.srcAdr,client,6);
        std::memcpy(dpack.mgmt.dstAdr,ap,6);
    }
    std::memcpy(dpack.mgmt.bssid,ap,6);
    dpack.mgmt.seqCtl = 0;
    dpack.code =1;
    dpack.fcs = 0;
            
    return;
}


void deauth::send_pack(void)
{

}
//char* deauth::ret_deauth(void)
//{
//    return (char*)(&this->pack);
//}
