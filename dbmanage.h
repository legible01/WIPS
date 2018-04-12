#include <iostream>
#include <cstdio>
#include <mysql/mysql.h>

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



public:
    dbmanage();
    ~dbmanage();
};

