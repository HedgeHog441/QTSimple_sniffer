#ifndef SNIFFER_H
#define SNIFFER_H
#include <ifaddrs.h>
#include <set>
#include <string>
#include <net/if.h>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netdb.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

#include "logger.h"


class sniffer
{
public:
    sniffer();
    ~sniffer();

    struct Filters{
        bool ARP = true;
        bool IPv4 = true;
        bool IPv6 = true;
        bool TCP = true;
        bool UDP = true;

        std::string ip_addr;
        int port;
    };

    const bool HEX = false;

    Filters filters;

    void scanInterface();
    void setInterface(const QString &arg);

    void start();
    void stop();

    bool isValidIP(const std::string& ip);

    int pc = 0;
    int pc_f = 0;

    const std::vector<std::string>& getInterfaces();

private:
    std::vector<std::string> interfaces;
    int activeInterfaceIndex = -1;

    std::thread main_thread;

    std::atomic<bool> is_running = false;

    int sock = -1;

    void run();

    void packetAnalizer(const char (&buf)[2049], int size);

};

#endif // SNIFFER_H
