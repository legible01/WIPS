#include "listload.h"
#include <typeinfo>
#include <cstring>


listLoad::listLoad()
{
//make map for dev list
//accessList
//getDevList();
//blackList
//whitelist


}
//basically macField = 0
int listLoad:: initTbl(MYSQL_RES* lRes,int macField = -1)
{

    int fCnt = mysql_num_fields(lRes);
    while((row = mysql_fetch_row(lRes)))
    {
        for(int cnt = 0; cnt<fCnt; cnt++)
        {
            if(cnt == macField)
            {
               char* intMac = row[0];
               //rintf("tec=%s",tec);
               tempMac = intMac;//MAC overload



            }
            printf("%12s",this->row[cnt]);
            //std::cout << typeid(*row[1]).name() <<'\n';//debug
        }
            printf("\n");


    }
    return 0;
}

