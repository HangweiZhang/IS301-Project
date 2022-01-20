#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <HeaderInfo.h>
#include <pcap.h>
#include "winsock2.h"
#include <QString>
#include "DataPackage.h"
#include <QDebug>

class CapThread : public QThread
{
    Q_OBJECT
public:
    CapThread(pcap_t *adhandle);

    void run();
    static QString byteToHex(u_char *str, int size);
    void setFlag();

    void ethernetHandle(DataPackage &data);
    void arpHandle(DataPackage &data);
    void ipHandle(DataPackage &data);
    void icmpHandle(DataPackage &data);
    void tcpHandle(DataPackage &data, int packageLen);
    void udpHandle(DataPackage &data);

private:
    pcap_t *adhandle;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    volatile bool flag;

signals:
    void sendData(DataPackage data);

};

#endif // CAPTHREAD_H
