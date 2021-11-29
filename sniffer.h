#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <pcap.h>
#define HAVE_REMOTE

QT_BEGIN_NAMESPACE
namespace Ui { class sniffer; }
QT_END_NAMESPACE

class sniffer : public QMainWindow
{
    Q_OBJECT

public:
    sniffer(QWidget *parent = nullptr);
    ~sniffer();

    void showNetworkCard();     // show the available network card
    int openAdapter();      // open the adapter

private slots:
    void on_comboBox_currentIndexChanged(int index);    // choose the device

private:
    Ui::sniffer *ui;
    pcap_if_t *alldevs;     // all the devices
    pcap_if_t *dev;     // device
    char errbuf[PCAP_ERRBUF_SIZE];      // npcap: errbuf
    pcap_t *adhandle;       // the chosen adapter
};
#endif // SNIFFER_H
