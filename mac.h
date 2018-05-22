#ifndef MAC_H
#define MAC_H
#include <cstdint>
#include <string>
#include <cstdlib>
#include <iostream>
#include <cstring>


#include <map>
#include <tuple>




class mac
{
public:
    mac();
    uint8_t macAddr[6];
    mac& operator =(char *strAddr)
    {
        std::string baseMac = "000000000000";
        baseMac.replace(12-(std::strlen(strAddr)),std::strlen(strAddr),strAddr);
        std::string te2;
        //printf("macLen = %d\n",strlen(strAddr));

        for(int cnt = 5;cnt>-1;cnt--)
        {
           // std::cout<<"string="<<baseMac<<'\n';
            int num=cnt*2;
            te2 = baseMac.substr(num,2);
            //std::cout<<"te2="<<te2<<'\n';
            macAddr[cnt] = (uint8_t)(std::stoi(te2,0,16));
            printf("%d\n",macAddr[cnt]);

        }

        //if()
    return *this;
    }
    bool operator<(const mac sMac)   const{
               return std::tie(macAddr[0],macAddr[1],macAddr[2],macAddr[3],macAddr[4],macAddr[5])<std::tie(sMac.macAddr[0],sMac.macAddr[1],sMac.macAddr[2],sMac.macAddr[3],sMac.macAddr[4],sMac.macAddr[5]);
    }

};

#endif // MAC_H
