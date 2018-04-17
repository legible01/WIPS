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


MYSQL_RES* dbmanage:: dbQuery(char * qStr)
{
    //qStr = "SHOW TABLES"
    if(mysql_query(&mysql, qStr))
    {
        printf("%s\n", mysql_error(&mysql));
        exit(1);
    }
    this->res = mysql_store_result(&mysql);
    return this->res;

}
void dbmanage::dbFree(void)
{
    mysql_free_result(this->res);
}
