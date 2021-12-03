#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "HeaderInfo.h"

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
   ~DataPackage();

   void setLen(u_int len);
   void setDataPointer(const u_char *pkt_data, u_int size);
   void setTimStamp(QString timeStamp);
   void setType(int type);
   void setInfo(QString info);

   QString getInfo();
   QString getProtocol();
};

#endif // DATAPACKAGE_H
