#include <iostream>
#include <cstdio>
#include <mysql/mysql.h>

#define WHITEAP 1
#define WHITESTATION 2
#define BLACKAP 3
#define BLACKSTATION 4


class dbmanage
{
private:
    struct{
        char const *dbHost ="localhost";
        char const *dbUser ="packethunter";
        char const *dbPass ="packethunter";
        char const *dbName ="PacketHunter";
    }DBInfo;
    MYSQL mysql;
    MYSQL_RES *res;



public:
    dbmanage();
    ~dbmanage();
    MYSQL_RES* dbQuery(char * qStr);
    void dbFree(void);

};

