#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <HeaderInfo.h>
#include <pcap.h>
#include <QDebug>

class CapThread : public QThread
{
    Q_OBJECT
public:
    CapThread(pcap_t *adhandle);
    void run();

private:
    pcap_t *adhandle;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
};

#endif // CAPTHREAD_H
