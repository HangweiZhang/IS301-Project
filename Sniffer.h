#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <pcap.h>
#define HAVE_REMOTE
#include "CapThread.h"
#include "HeaderInfo.h"
#include "DataPackage.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Sniffer; }
QT_END_NAMESPACE

class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    Sniffer(QWidget *parent = nullptr);
    ~Sniffer();

    void showNetworkCard();     // show the available network card
    int openAdapter();      // open the adapter

private slots:
    void on_comboBox_currentIndexChanged(int index);    // choose the device

private:
    Ui::Sniffer *ui;
    pcap_if_t *alldevs;     // all the devices
    pcap_if_t *dev;     // device
    char errbuf[PCAP_ERRBUF_SIZE];      // npcap: errbuf
    pcap_t *adhandle;       // the chosen adapter
    CapThread *capthread;       // capture thread
};
#endif // SNIFFER_H
