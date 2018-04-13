#include <iostream>
#include <pcap/pcap.h>
#include <list>


class devsearch
{
private:
    pcap_if_t *recvNetDev;
    pcap_if_t *netDev;
    char **devAddr;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    typedef std::list<char *>devAddrs;
    devAddrs devAddrList;
public:
    devsearch();
    bool GetDevList(void);
};
