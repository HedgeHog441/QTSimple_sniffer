#include "sniffer.h"
#include <QDebug>

sniffer::sniffer() {

     qDebug() << "sniffer()";

}

sniffer::~sniffer(){

    qDebug() << "~sniffer()";

}

void sniffer::scanInterface(){
    struct ifaddrs *addrs, *tmp;

    if(getifaddrs(&addrs) == -1){
        logger::log("Get Interface Address fail", logger::ERROR);
        return;
    }

    tmp = addrs;
    while(tmp){
        if(tmp->ifa_addr->sa_family == AF_PACKET){
            interfaces.push_back(tmp->ifa_name);
        }
        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
}

void sniffer::setInterface(const QString &arg){
    activeInterfaceIndex = if_nametoindex(arg.toStdString().c_str());
}

const std::vector<std::string>& sniffer::getInterfaces(){
    return interfaces;
}

void sniffer::run(){

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if(sock == -1){
        logger::log("Socket error", logger::ERROR);
        return;
    }

    //logger::log(QString("sock = %1").arg(sock));

    sockaddr_ll addr{};

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = activeInterfaceIndex;


    if((bind(sock, (struct sockaddr*)&addr, sizeof(addr)))< 0){
        logger::log("Bind failed", logger::ERROR);
        //qDebug() << "err - " << errno;
        return;
    }

    char buf[2049];
    is_running = true;

    logger::log("Прослушивание начато", logger::OK);

    while(is_running){

        int bytes_received = recv(sock, buf, 2048, 0);

        if(bytes_received <= 14 or buf[0] == '\0'){
            continue;
        }

        buf[bytes_received] = '\0';

        packetAnalizer(buf, bytes_received); // Start Analize and logging result;

    }
}

void sniffer::start(){
    if(main_thread.joinable()){
        return;
    }
    main_thread = std::thread(&sniffer::run, this);
}

void sniffer::stop(){

    is_running = false;

    // ПРЕРВАТЬ recv!!!
    shutdown(sock, SHUT_RDWR);

    if(main_thread.joinable()){
        main_thread.join();
    }

    logger::log("Прослушивание остановлено", logger::OK);
}

bool sniffer::isValidIP(const std::string& ip){
    sockaddr_in sa;

    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr) ) == 1;
}

void sniffer::packetAnalizer(const char(&buf)[2049], int size){

    bool isLogged = false;

    struct ethhdr *eth = (struct ethhdr *)buf;
    uint16_t ethProto = ntohs(eth->h_proto);

    //ARP

    if(ethProto == ETH_P_ARP){
        if(filters.ARP){
            QString macSrc = QByteArray::fromRawData((const char*)eth->h_source, 6).toHex(':');
            QString macDst = QByteArray::fromRawData((const char*)eth->h_dest, 6).toHex(':');
            logger::log(QString("%1 -> %2").arg(macSrc).arg(macDst), "ARP");
        }
    }

    // IP4

    else if(ethProto == ETH_P_IP){
        struct iphdr *ip = (struct iphdr *)(buf + 14);
        int ip_len = ip->ihl * 4;
        uint8_t l4_proto = ip->protocol;

        char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), s_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->saddr), d_ip, INET_ADDRSTRLEN);

        int l4_header_len = 0;
        QString mainRes;
        QString prefix;

        if(l4_proto == IPPROTO_TCP and filters.TCP){
            struct tcphdr *tcp = (struct tcphdr *)(buf + 14 + ip_len);
            mainRes = QString("%1:%2 -> %3:%4").arg(s_ip).arg(ntohs(tcp->source)).arg(d_ip).arg(tcp->dest);
            prefix = "TCP";
            isLogged = true;
        }
        else if(l4_proto == IPPROTO_UDP and filters.UDP){
            struct udphdr *udp = (struct udphdr *)(buf + 14 + ip_len);
            mainRes = QString("%1:%2 -> %3:%4").arg(s_ip).arg(ntohs(udp->source)).arg(d_ip).arg(udp->dest);
            prefix = "UDP";
            isLogged = true;
        }
        else if(filters.IPv4 and !filters.TCP and !filters.UDP){
            mainRes = QString("%1 -> %2").arg(s_ip).arg(d_ip);
            prefix = "???";
            isLogged = true;
        }

        if(isLogged){
            logger::log(mainRes, prefix);

            int total_headers = ip_len+ l4_header_len;
            if(size > total_headers){
                int p_size = size - total_headers;

                QByteArray payloadData = QByteArray::fromRawData((const char*)(buf + total_headers), qMin(p_size, 64));

                QString dataText = QString::fromUtf8(payloadData).simplified();

                if(!dataText.isEmpty()){
                    logger::log(dataText, "DATA");
                }
                else{
                    logger::log(payloadData.toHex(' '), "DATA_HEX");
                }
            }
        }
    }

    // IP6

    else if(ethProto == ETH_P_IPV6 and filters.IPv6){
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(buf + 14);

        char s_ip6[INET6_ADDRSTRLEN], d_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), s_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6->ip6_dst), d_ip6, INET6_ADDRSTRLEN);

        uint8_t next_proto = ip6->ip6_nxt;
        int l4_offset = 14 + 40; //
        int l4_header_len = 0;
        QString mainRes(QString("%1 -> %2").arg(s_ip6).arg(d_ip6));
        QString prefix = "IPv6";

        if(next_proto == IPPROTO_TCP and filters.TCP){
            struct tcphdr *tcp = (struct tcphdr *)(buf + l4_offset);
            mainRes = QString("[%1:%2] -> [%3:%4]").arg(s_ip6).arg(ntohs(tcp->source)).arg(d_ip6).arg(ntohs(tcp->dest));
            l4_header_len = tcp->doff * 4;
            prefix = "TCP6";
            isLogged = true;
        }
        else if(next_proto == IPPROTO_UDP and filters.UDP){
            struct udphdr *udp = (struct udphdr *)(buf + l4_offset);
            mainRes = QString("[%1:%2] -> [%3:%4]").arg(s_ip6).arg(ntohs(udp->source)).arg(d_ip6).arg(ntohs(udp->dest));
            l4_header_len = 8;
            prefix = "UDP6";
            isLogged = true;
        }
        else{
            isLogged = true;
        }

        if(isLogged){
            logger::log(mainRes, prefix);

            int total_headers = l4_offset + l4_header_len;

            if(size > total_headers){

                int p_size = size - total_headers;

                QByteArray data = QByteArray::fromRawData((const char*)(buf + total_headers), qMin(p_size, 64));
                QString dataText = QString::fromUtf8(data).simplified();

                if(!dataText.isEmpty()) logger::log(dataText, "DATA");
                else logger::log(data.toHex(' '), "DATA_HEX");

            }
        }
    }

    logger::pc_inc(isLogged);
    logger::log("", logger::EMPTY);

}
