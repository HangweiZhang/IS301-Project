#include <DataPackage.h>

DataPackage::DataPackage()
{
    this->type = 0;
    this->len = 0;
    this->timeStamp = "";
    this->pkt_data = nullptr;

    qRegisterMetaType<DataPackage>();
}

QString DataPackage::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0; i < size; i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

void DataPackage::setLen(u_int len)
{
    this->len = len;
}

void DataPackage::setDataPointer(const u_char *pkt_data, u_int size)
{
    this->pkt_data = (u_char*)malloc(size);
    if(this->pkt_data != nullptr)
        memcpy((char*)(this->pkt_data),pkt_data,size);
    else this->pkt_data = nullptr;
}

void DataPackage::setTimeStamp(QString timeStamp)
{
    this->timeStamp = timeStamp;
}

void DataPackage::setType(int type)
{
    this->type = type;
}

void DataPackage::setInfo(QString info)
{
    this->info = info;
}

QString DataPackage::getTimeStamp()
{
    return this->timeStamp;
}

QString DataPackage::getLen()
{
    return QString::number(this->len);
}

QString DataPackage::getInfo()
{
    return this->info;
}

QString DataPackage::getProtocol()
{
    switch (this->type) {
    case 1:
        return "ARP";

    case 2:
        return "ICMP";

    case 3:
        return "TCP";

    case 4:
        return "UDP";

    default:
        return "Unknown protocol";
    }
}

int DataPackage::getType()
{
    return this->type;
}

QString DataPackage::getSrc()
{
    if(this->type == 1)
        return getArpEtherSrc();
    else return getIpSrc();
}

QString DataPackage::getDes()
{
    if(this->type == 1)
        return getArpEtherDes();
    else return getIpDes();
}

// mac info
QString DataPackage::getMacSrc()
{
    ETHER_HEADER *ether;
    ether = (ETHER_HEADER*)this->pkt_data;
    u_char *addr;
    QString res = "";

    addr = ether->ether_src;
    if(addr){
        res = byteToHex(addr,1) + ":"
                + byteToHex((addr+1),1) + ":"
                + byteToHex((addr+2),1) + ":"
                + byteToHex((addr+3),1) + ":"
                + byteToHex((addr+4),1) + ":"
                + byteToHex((addr+5),1);
        if(res == "FF:FF:FF:FF:FF:FF")
            res = "FF:FF:FF:FF:FF:FF(Broadcast)";
    }
    return res;
}

QString DataPackage::getMacDes()
{
    ETHER_HEADER *ether;
    ether = (ETHER_HEADER*)this->pkt_data;
    u_char *addr;
    QString res = "";

    addr = ether->ether_des;
    if(addr){
        res = byteToHex(addr,1) + ":"
                + byteToHex((addr+1),1) + ":"
                + byteToHex((addr+2),1) + ":"
                + byteToHex((addr+3),1) + ":"
                + byteToHex((addr+4),1) + ":"
                + byteToHex((addr+5),1);
        if(res == "FF:FF:FF:FF:FF:FF")
            res = "FF:FF:FF:FF:FF:FF(Broadcast)";
    }
    return res;
}
QString DataPackage::getMacType()
{
    ETHER_HEADER *ether;
    ether = (ETHER_HEADER*)this->pkt_data;
    u_short ether_type = ntohs(ether->ether_type);
    QString res = "";

    switch (ether_type) {
    case 0x0800:
        res = "IPv4(0x800)";
        break;

    case 0x0806:
        res = "ARP(0x0806)";
        break;

    default:
        break;
    }
    return res;
}

// ip info
QString DataPackage::getIpSrc()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    sockaddr_in srcAddr;

    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPackage::getIpDes()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);

    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}

QString DataPackage::getIpChecksum()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ntohs(ip->checksum),16);
}

QString DataPackage::getIpProtocol()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:
        return "ICMP (1)";
    case 6:
        return "TCP (6)";
    case 17:
        return "UDP (17)";
    default:
        return "";
    }
}

QString DataPackage::getIpTTL()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ip->ttl);
}

QString DataPackage::getIpOffset()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}

QString DataPackage::getIpR()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    int R = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(R);
}

QString DataPackage::getIpDF()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
}

QString DataPackage::getIpMF()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}

QString DataPackage::getIpIdentification()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ntohs(ip->identification),16);
}

QString DataPackage::getIpTotalLength()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ntohs(ip->total_length));
}

QString DataPackage::getIpTOS()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ntohs(ip->TOS));
}

QString DataPackage::getIpHeaderLength()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    QString res = "";

    int length = ip->ver_h_length & 0x0F;
    res = QString::number(length * 4) + " bytes (" + QString::number(length) + ")";
    return res;
}

QString DataPackage::getIpVersion()
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(this->pkt_data + 14);
    return QString::number(ip->ver_h_length >> 4);
}

QString DataPackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_data + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}

QString DataPackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_data + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}

// arp info
QString DataPackage::getArpHardwareType()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001)
        res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}

QString DataPackage::getArpProtocolType()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800)
        res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}

QString DataPackage::getArpMacLength()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    return QString::number(arp->mac_length);
}

QString DataPackage::getArpIpLength()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    return QString::number(arp->ip_length);
}

QString DataPackage::getArpOP()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1)
        res  = "request(1)";
    else if(code == 2)
        res = "reply(2)";
    return res;
}

QString DataPackage::getArpEtherSrc()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    u_char *addr;
    QString res = "";
    addr = arp->src_eth_addr;
    if(addr){
        res = byteToHex(addr,1) + ":"
                + byteToHex((addr+1),1) + ":"
                + byteToHex((addr+2),1) + ":"
                + byteToHex((addr+3),1) + ":"
                + byteToHex((addr+4),1) + ":"
                + byteToHex((addr+5),1);
    }
    return res;
}

QString DataPackage::getArpIpSrc()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    u_char *addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));
    return srcIp;
}

QString DataPackage::getArpEtherDes()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    u_char *addr;
    QString res = "";
    addr = arp->des_eth_addr;
    if(addr){
        res = byteToHex(addr,1) + ":"
                + byteToHex((addr+1),1) + ":"
                + byteToHex((addr+2),1) + ":"
                + byteToHex((addr+3),1) + ":"
                + byteToHex((addr+4),1) + ":"
                + byteToHex((addr+5),1);
    }
    return res;
}

QString DataPackage::getArpIpDes()
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(this->pkt_data + 14);
    u_char *addr = arp->des_ip_addr;
    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));
    return desIp;
}

// icmp info
QString DataPackage::getIcmpType()
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(icmp->type));
}

QString DataPackage::getIcmpCode()
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(icmp->code));
}

QString DataPackage::getIcmpChecksum()
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}

// 仅处理请求和应答报文格式
QString DataPackage::getIcmpIdentification()
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}

QString DataPackage::getIcmpSequence()
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(icmp->sequence));
}

QString DataPackage::getIcmpData(int size){
    char *icmp;
    icmp = (char*)(pkt_data + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}

// tcp info
QString DataPackage::getTcpSrc()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    int port = ntohs(tcp->src_port);
    if(port == 443)
        return "https(443)";
    return QString::number(port);
}

QString DataPackage::getTcpDes()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    int port = ntohs(tcp->des_port);
    if(port == 443)
        return "https(443)";
    return QString::number(port);
}

QString DataPackage::getTcpSequence()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohl(tcp->sequence));
}
QString DataPackage::getTcpAck()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohl(tcp->ack));
}

QString DataPackage::getTcpHeaderLength()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    int length = (tcp->header_length >> 4);
    return QString::number(length * 4) + " bytes (" + QString::number(length) + ")";
}

QString DataPackage::getTcpRawHeaderLength(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(tcp->header_length >> 4);
}

QString DataPackage::getTcpFlags()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(tcp->flags,16);
}

QString DataPackage::getTcpPSH(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}

QString DataPackage::getTcpACK(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}

QString DataPackage::getTcpSYN(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}

QString DataPackage::getTcpURG(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}

QString DataPackage::getTcpFIN(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}

QString DataPackage::getTcpRST(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(pkt_data + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}

QString DataPackage::getTcpWindow()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(tcp->window_size));
}

QString DataPackage::getTcpChecksum()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}

QString DataPackage::getTcpUrgent()
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(this->pkt_data + 14 + 20);
    return QString::number(ntohs(tcp->urgent));
}

// udp info
QString DataPackage::getUdpSrc()
{
    UDP_HEADER *udp;
    udp = (UDP_HEADER*)(this->pkt_data + 20 + 14);
    int port = ntohs(udp->src_port);
    if(port == 53)
        return "domain(53)";
    else return QString::number(port);
}

QString DataPackage::getUdpDes()
{
    UDP_HEADER *udp;
    udp = (UDP_HEADER*)(this->pkt_data + 20 + 14);
    int port = ntohs(udp->des_port);
    if(port == 53)
        return "domain(53)";
    else return QString::number(port);
}

QString DataPackage::getUdpDataLength()
{
    UDP_HEADER *udp;
    udp = (UDP_HEADER*)(this->pkt_data + 20 + 14);
    return QString::number(ntohs(udp->data_length));

}

QString DataPackage::getUdpChecksum()
{
    UDP_HEADER *udp;
    udp = (UDP_HEADER*)(this->pkt_data + 20 + 14);
    return QString::number(ntohs(udp->checksum),16);
}
