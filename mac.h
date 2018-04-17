#ifndef MAC_H
#define MAC_H
#include <cstdint>
#include <string>
#include <cstdlib>
#include <iostream>
#include <cstring>



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
};

#endif // MAC_H
