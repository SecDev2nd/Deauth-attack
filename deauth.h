#pragma pack(push, 1)
struct Radiotap {
    uint8_t it_version;     /* set to 0 , 1byte*/
    uint8_t it_pad;         /* 1byte */
    uint16_t it_len;        /* entire length , 2byte , 대부분 24임*/
    uint32_t it_present;    /* fields present */
    uint32_t padding[4];
};

//Deauth일 경우 그대로 사용하고
// Auth일 경우 변경해서
struct DeauthFrame {
    uint16_t type; // Auth일 경우 0x00b0
    uint16_t duration; //frame control필드까지 합쳐져서 2byte
    uint8_t destination_address[6]; // == Receiver Address
    uint8_t source_address[6]; // == Transmitter Address
    uint8_t bssid[6];
    uint16_t fragNseq_number;
};

struct FixedParameter {
    uint16_t reason_code; // or 0x0003
};

struct AuthFixedParameter {
    uint16_t Algorithm;
    uint16_t SEQ;
    uint16_t Status_code;
};

struct Packet {
    Radiotap radiotap;
    DeauthFrame deauth;
    FixedParameter fixed;
};

struct AuthPacket {
    Radiotap radiotap;
    DeauthFrame auth;
    AuthFixedParameter AuthParameter;
};
#pragma pack(pop)
