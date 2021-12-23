#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "HeaderInfo.h"
#include "winsock2.h"
#include <QMetaType>

class DataPackage
{
private:
   u_int len;    // data package length
   QString timeStamp;   // data package timestamp
   int type;    // type: arp(1), icmp(2), tcp(3), udp(4)
   QString info;    // a brief introduction

public:
   u_char *pkt_data;    // package pointer

public:
   DataPackage();
   ~DataPackage() = default;

   static QString byteToHex(u_char *str, int size);

   void setLen(u_int len);
   void setDataPointer(const u_char *pkt_data, u_int size);
   void setTimeStamp(QString timeStamp);
   void setType(int type);
   void setInfo(QString info);

   QString getTimeStamp();
   QString getSrc();
   QString getDes();
   QString getLen();
   QString getInfo();
   QString getProtocol();
   int getType();

   // mac info
   // ethernet header
   QString getMacSrc();
   QString getMacDes();
   QString getMacType();

   // ip info
   // ip header
   QString getIpSrc();
   QString getIpDes();
   QString getIpChecksum();
   QString getIpProtocol();
   QString getIpTTL();
   QString getIpOffset();
   QString getIpR();
   QString getIpDF();
   QString getIpMF();
   QString getIpIdentification();
   QString getIpTotalLength();
   QString getIpTOS();
   QString getIpHeaderLength();
   QString getIpVersion();

   // arp info
   // arp header
   QString getArpHardwareType();
   QString getArpProtocolType();
   QString getArpMacLength();
   QString getArpIpLength();
   QString getArpOP();
   QString getArpEtherSrc();
   QString getArpIpSrc();
   QString getArpEtherDes();
   QString getArpIpDes();

   // icmp info
   // icmp header
   QString getIcmpType();
   QString getIcmpCode();
   QString getIcmpChecksum();
   // 仅处理请求和应答报文格式
   QString getIcmpIdentification();
   QString getIcmpSequence();

   // tcp info
   // tcp header
   QString getTcpSrc();
   QString getTcpDes();
   QString getTcpSequence();
   QString getTcpAck();
   QString getTcpHeaderLength();
   QString getTcpFlags();
   QString getTcpWindow();
   QString getTcpChecksum();
   QString getTcpUrgent();

   // udp info
   // udp header
   QString getUdpSrc();
   QString getUdpDes();
   QString getUdpDataLength();
   QString getUdpChecksum();

};

Q_DECLARE_METATYPE(DataPackage);

#endif // DATAPACKAGE_H
