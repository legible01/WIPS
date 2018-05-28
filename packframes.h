#ifndef PACKFRAMES_H
#define PACKFRAMES_H
#include "cstdint"
#include <bitset>


class packframes
{
public:
#pragma pack(push,1)
/*
     typedef struct radiotap_hdr_present_flag_word{
        uint8_t TSFT                : 1;
        uint8_t Flags               : 1;
        uint8_t Rate                : 1;
        uint8_t Channel             : 1;
        uint8_t FHSS                : 1;
        uint8_t dbm_antenna_signal  : 1;
        uint8_t dbm_antenna_noise   : 1;
        uint8_t Lock_quality        : 1;

        uint8_t TX_attenuation      : 1;
        uint8_t db_TX_attenuation   : 1;
        uint8_t dbm_TX_power        : 1;
        uint8_t Antenna             : 1;
        uint8_t db_Antenna_signal   : 1;
        uint8_t db_Antenna_noise    : 1;
        uint8_t RX_flags            : 1;
        uint8_t non_data            : 3;
        uint8_t Channel_plus        : 1;

        uint8_t mcs_information     : 1;
        uint8_t a_mpdu_status       : 1;
        uint8_t none_data1          :1;
        uint8_t none_data2          :1;
        uint8_t reserved1           :6;
        uint8_t radiotap_NS_next    :1;
        uint8_t vendor_NS_next      :1;
        uint8_t Ext                 :1;



    }pflg_word;*/
 //--------------------------------radiotap header setting
    enum RTH_pflg {
        RTH_TSFT = 0,
        RTH_FLAGS = 1,
        RTH_RATE = 2,
        RTH_CHANNEL = 3,
        RTH_FHSS = 4,
        RTH_DBM_ANTSIGNAL = 5,
        RTH_DBM_ANTNOISE = 6,
        RTH_LOCK_QUALITY = 7,
        RTH_TX_ATTENUATION = 8,
        RTH_DB_TX_ATTENUATION = 9,
        RTH_DBM_TX_POWER = 10,
        RTH_ANTENNA = 11,
        RTH_DB_ANTSIGNAL = 12,
        RTH_DB_ANTNOISE = 13,
        RTH_RX_FLAGS = 14,
        RTH_TX_FLAGS = 15,
        RTH_RTS_RETRIES = 16,
        RTH_DATA_RETRIES = 17,
        RTH_XChannel = 18,
        RTH_MCS = 19,
        RTH_AMPDU_STATUS = 20,
        RTH_VHT = 21,
        RTH_TIMESTAMP = 22,
        RTH_RADIOTAP_NAMESPACE = 29,
        RTH_VENDOR_NAMESPACE = 30,
        RTH_EXT = 31
    };

/*flag_to_size_rth
    {
        TSFT                0    size= 8 allign=8
        flags               1    size= 1 allign=1;
        rate                2    size= 1 allign=1
        channel             3    size= 4 allign=2

        fhss                4    size= 2 allign=???(2?)
        antena signal       5    size= 1 allign=1;dbm
        antena noise        6    size= 1 allign=1;
        lock quality        7    size= 2 allign=2

        tx attenuation      8    size= 2 allign=2
        db_tx_attenuation   9    size= 2 allign=2
        dbm_tx_power        10   size= 1 allign=1
        antena              11   size= 1 allign=1

        db_antena_signal    12   size= 1 allign=1
        db_antena_noise     13   size= 1 allign=1
        rx_flags            14   size= 2 allign=2
                            15

                            16
                            17
                            18
        mcs                 19   size= 3 allign=1

        mpdu                20   size= 6 allign=4
        vht                 21   size=12 allign=2
        timestamp           22   size=12 allign=8
        vendor_namespace    30   size=6  allign=2


        //uint8_t radiotap_ns_next;*
        //uint8_t Vendor_NS_next ;
        //uint8_t ext;*
        // is need but don't need size?
    }rth_flag_size;*/
        int pflg_size[32]={8,1,1,4,2,1,1,2,2,2,1,1,1,1,2,0,0,0,0,3,6,12,12,0,0,0,0,0,0,0,6,0};
                           //        4       8      12      16      20        24      28      32
        int pflg_allign[32]={8,1,1,2,2,1,1,2,2,2,1,1,1,1,2,0,0,0,0,1,4,2,8,0,0,0,0,0,0,0,2,0};
                             //        4       8      12      16      20      24      28      32
    typedef struct radiotap_hdr_present_flags{
        std::bitset<32> pflg1;
        std::bitset<32> pflg2;
    }pflgs;

    typedef struct radiotap_80211_hdr{
        uint8_t rth_version;
        uint8_t rth_pad;
        uint16_t rth_length;
        pflgs rth_present_flg;
    }rth;
//-------------------abstract datas(rth)
    typedef struct radiotap_80211_hdr_data{
        uint8_t* rss;
        uint16_t* channel;

    }rth_data;
    //void
    //struct management frame
//----------------80211 frame----------------------------


typedef struct FrameCtrl
{
    uint8_t   protocolVer    : 2;
    uint8_t   type           : 2;
    uint8_t   subType        : 4;
    uint8_t   toDs           : 1;
    uint8_t   fromDs         : 1;
    uint8_t   moreFlag       : 1;
    uint8_t   retry          : 1;
    uint8_t   powerMgmt      : 1;
    uint8_t   moreData       : 1;
    uint8_t   protectedFrame : 1;
    uint8_t   order          : 1;
}FC;

struct ManagementFrame
{
           FC  frameCtrl;  //2 bytes
           uint16_t   duration;   //2 bytes
           uint8_t    addr1[6];   //6 bytes
           uint8_t    addr2[6];   //6 bytes
           uint8_t    addr3[6];   //6 bytes
           uint16_t   seq_ctrl;   //2 bytes
};

struct BeaconFrameBody
{
    uint64_t  timestamp;
    uint16_t  beaconInterval;
    uint16_t  capacityInformation;
};

struct TagBody
{
    uint8_t   elementID;
    uint8_t   tagLength;
};

struct WifiName
{
    uint8_t ssid[32];
};
//void fakeAp(const uint8_t *);


#pragma pack(pop)

    packframes();
    //void get_fucking_addr();
};

#endif // PACKFRAMES_H
