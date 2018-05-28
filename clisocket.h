#ifndef CLISOCKET_H
#define CLISOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>




class clisocket
{
private:

    int clientSocket;

    //uint8_t recvBuf[];
    char * inetAdr;
    char * portNo;
    struct sockaddr_in serverAdr;



public:
    clisocket();
};

#endif // CLISOCKET_H
