#include "CapThread.h"

CapThread::CapThread(pcap_t *adhandle)
{
    this->adhandle = adhandle;
    this->flag = false;
}

CapThread::~CapThread()
{

}

void CapThread::setFlag()
{
    this->flag = !this->flag;
}

QString CapThread::byteToHex(u_char *str, int size){
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

void CapThread::run()
{
    int res;
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
        if(!flag)
            break;

        // 捕获超时
        if(res == 0)
            continue;

        // 将时间戳转换成可识别的格式
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

        // 解析数据
        // 存于DataPackage类的data中
        DataPackage data;
        u_int len = header->len;
        data.setLen(len);
        data.setDataPointer(pkt_data, len);
        QString timeStamp = timestr;
        data.setTimStamp(timeStamp);
        ethernetHandle(data);

        // 构建data成功
        // 发送data
        if(data.pkt_data){
            qDebug() << data.getProtocol() << " " << data.getInfo();
        }
    }
}

void CapThread::ethernetHandle(DataPackage &data)
{
    ETHER_HEADER *ether;
    ether = (ETHER_HEADER *)pkt_data;
    ether->ether_type = ntohs(ether->ether_type);

    switch (ether->ether_type) {
    case 0x0806:    // ARP
        data.setType(1);
        arpHandle(data);
        break;

    case 0x0800:    // IPv4
        ipHandle(data);
        break;

    //case 0x86dd:    // todo: IPv6
    default:    // undefined types
        break;
    }
}

void CapThread::arpHandle(DataPackage &data)
{
    if(data.pkt_data){
        ARP_HEADER *arp;
        arp = (ARP_HEADER*)(data.pkt_data + 14);

        u_short op = ntohs(arp->op_code);
        QString res = "";

        u_char *addr = arp->des_ip_addr;

        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));

        addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));

        u_char* srcEthTemp = arp->src_eth_addr;

        QString srcEth = byteToHex(srcEthTemp,1) + ":"
                + byteToHex((srcEthTemp+1),1) + ":"
                + byteToHex((srcEthTemp+2),1) + ":"
                + byteToHex((srcEthTemp+3),1) + ":"
                + byteToHex((srcEthTemp+4),1) + ":"
                + byteToHex((srcEthTemp+5),1);

        switch (op){
        case 1:
            res  = "Who has " + desIp + "? Tell " + srcIp;
            break;

        case 2:
            res = srcIp + " is at " + srcEth;
            break;

        default:
            break;
        }
        data.setInfo(res);
    }
}

void CapThread::ipHandle(DataPackage &data)
{
    if(data.pkt_data){
        IP_HEADER *ip;
        ip = (IP_HEADER*)(data.pkt_data + 14);

        int protocol = ip->protocol;    // ICMP(1), TCP(6), UDP(17)
        int packageLen = (htons(ip->total_length) - (ip->ver_h_length & 0x0F) * 4);

        switch (protocol) {
        case 1:     // ICMP
            data.setType(2);
            icmpHandle(data);
            break;

        case 6:     // TCP
            data.setType(3);
            tcpHandle(data, packageLen);
            break;

        case 17:    // UDP
            data.setType(4);
            udpHandle(data);
            break;

        default:
            break;
        }
    }
}

void CapThread::icmpHandle(DataPackage &data)
{
    if(data.pkt_data){
        ICMP_HEADER *icmp;
        icmp = (ICMP_HEADER*)(data.pkt_data + 20 + 14);

        u_char type = icmp->type;
        u_char code = icmp->code;
        QString res = "";

        switch (type){
        case 0:
            res = "Echo response (ping)";
            break;

        case 3:{
            switch (code){
            case 0:
                res = "Network unreachable";
                break;

            case 1:
                res = "Host unreachable";
                break;

            case 2:
                res = "Protocol unreachable";
                break;

            case 3:
                res = "Port unreachable";
                break;

            case 4:
                res = "Fragmentation is required, but DF is set";
                break;

            case 5:
                res = "Source route selection failed";
                break;

            case 6:
                res = "Unknown target network";
                break;

            default:
                break;
            }
            break;}

        case 4:
            res = "Source station suppression [congestion control]";
            break;

        case 5:
            res = "Relocation";
            break;

        case 8:
            res = "Echo request (ping)";
            break;

        default:
            break;
        }
        data.setInfo(res);
    }
}

void CapThread::tcpHandle(DataPackage &data, int packageLen)
{
    if(data.pkt_data){
        TCP_HEADER *tcp;
        tcp = (TCP_HEADER*)(data.pkt_data + 14 + 20);

        u_short src = ntohs(tcp->src_port);
        u_short des = ntohs(tcp->des_port);

        QString res = "";

        int delta = (tcp->header_length >> 4) * 4;
        int tcpPayLoad = packageLen - delta;

        res += QString::number(src) + "->" + QString::number(des);
        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            res += " [" + flag + "]";
            u_int sequeue = ntohl(tcp->sequence);
            u_int ack = ntohl(tcp->ack);
            u_short window = ntohs(tcp->window_size);
            res += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
        }
        data.setInfo(res);
    }
}

void CapThread::udpHandle(DataPackage &data)
{
    if(data.pkt_data){
        UDP_HEADER *udp;
        udp = (UDP_HEADER*)(data.pkt_data + 14 + 20);
        u_short des = ntohs(udp->des_port);
        u_short src = ntohs(udp->src_port);

        QString res = QString::number(src) + "->" + QString::number(des);
        res += " len=" + QString::number(ntohs(udp->data_length));
        data.setInfo(res);
    }
}
