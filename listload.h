#include <cstdio>
#include <iostream>
#include <list>
#include <pcap/pcap.h>
#include <mysql/mysql.h>



class listLoad
{

    private:
    //dev list variable
    pcap_if_t *recvNetDev;
    pcap_if_t *netDev;
    char **devAddr;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    typedef std::list<char *>devAddrs;
    devAddrs devAddrList;
    //typedef std::list<char *>

    typedef struct
    {
        char *server;
        char *user;
        char *password;
        char *database;
    }dbConnectInfo;
    dbConnectInfo mysqlDb;
    MYSQL *dbHandle;

    //whitelist
    //typedef std::
   
    
    public:
    bool GetDevList();
    void PrintDbInfo();
    //MYSQL* mysql_connection_setup{dbConnectInfo;}
    listLoad()
    {
        //std::list<char *>devAddrs;

        //mysqlDb.
        //dbConnectInfo mysqlDb;



    };
};


bool listLoad:: GetDevList(void)
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
    //if not null then use inital list


    status = true;
    return status;
}
void listLoad:: PrintDbInfo(void)
{

    dbHandle = mysql_init(NULL);
    if(dbHandle == NULL)
    {
        fprintf(stderr,"%s\n",mysql_error(dbHandle));
        // need error status response
    }

    if(mysql_real_connect(dbHandle,"localhost","root","5111",NULL,0,NULL,0) == NULL)
    {
        fprintf(stderr,"%s\n",mysql_error(dbHandle));
        mysql_close(dbHandle);

        // need error status response
    }

    //mysql_query(dbHandle,"SHOW DATABASES;")
    if(mysql_query(dbHandle,"SHOW DATABASES;"))
    {
        fprintf(stderr,"%s\n",mysql_error(dbHandle));
        mysql_close(dbHandle);

    }else{
    int fields ;
    MYSQL_ROW	row;
    MYSQL_RES *dbRes = mysql_store_result(dbHandle);
        //printf("%s\n",dbRes);
    fields = mysql_num_fields(dbRes) ;

        while( ( row = mysql_fetch_row( dbRes ) ))
        {
            for(int cnt = 0 ; cnt < fields ; ++cnt)
                printf("%12s ", dbRes[cnt]) ;

            printf("\n") ;
        }


    mysql_free_result(dbRes);
    }
    mysql_close(dbHandle);

    printf("Mysql =  %s\n", mysql_get_client_info());
}

