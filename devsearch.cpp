#include "devsearch.h"

devsearch::devsearch()
{
}
bool devsearch:: GetDevList(void)
{
    bool status = false;
    //find dev
    if(pcap_findalldevs(&(this->recvNetDev),this->pcap_errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", pcap_errbuf);
        return status;
    };

    //if make database then check saved data in this line.
    //send_device list to java or list?

    int current_number = 0;
    for(netDev = recvNetDev; netDev!=NULL;netDev = netDev->next)
    {

            devAddrList.push_back(netDev->name);
            std::cout<<devAddrList.back()<<std::endl;
            current_number++;


    }
}
