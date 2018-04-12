#include "dbmanage.h"

dbmanage::dbmanage()
{

    mysql_init(&this->mysql);

    if(!mysql_real_connect(&mysql,DBInfo.dbHost,DBInfo.dbUser,DBInfo.dbPass,DBInfo.dbName,3306,(char *)NULL, 0))
    {
        printf("%s\n",mysql_error(&mysql));
        exit(1);
    }
    printf("성공적으로 연결되었습니다.\n") ;
}

dbmanage::~dbmanage()
{
    mysql_close(&mysql);
}
