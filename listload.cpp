#include "listload.h"


listLoad::listLoad()
{
//make map for dev list
//accessList
    //getDevList();
//blackList
//whitelist

}
int listLoad:: initList(MYSQL_RES* tt)
{
    MYSQL_ROW   row;
    fCnt = mysql_num_fields(tt);

    while((row = mysql_store))



    return 0;
}
