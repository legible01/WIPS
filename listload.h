#include <cstdio>
#include <iostream>
#include <list>
#include <pcap/pcap.h>

class listLoad
{

    private:
    //dev list variable
    pcap_if_t *recvNetDev;
    pcap_if_t *netDev;
    char **devAddr;
    int test_var;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    typedef std::list<char *>devAddrs;
    devAddrs devAddrList;
    //typedef std::list<char *>

    public:
    bool getDevList();



    listLoad()
    {
        //std::list<char *>devAddrs;

    };
};


bool listLoad:: getDevList(void)
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
    //printf("%s",devAddrList[0]);
    //for(std::list<char*>::iterator iter = devAddrList.begin(); iter != devAddrList.end(); iter++){
     //  std::cout<<*iter<<std::endl;
    //}
    //printf("\nhere\n");
    printf("%d\n",test_var);
    if(test_var == NULL)
       printf("\ntestvar is null");


    status = true;
    return status;
}

