#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <pcap.h>
#define HAVE_REMOTE
#include "CapThread.h"
#include "HeaderInfo.h"
#include "DataPackage.h"
#include <QVector>
#include <QtDebug>

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
    void showARPtree(int row);  // show the detailed information(ARP)
    void showIPtree(int row);  // show the detailed information(IP)

public slots:
    void handleData(DataPackage data);      // handle the recieved data

private slots:
    void on_comboBox_currentIndexChanged(int index);    // choose the device

    void on_tableWidget_cellClicked(int row, int column);   // choose the data

    void on_lineEdit_textChanged(const QString &arg1);  // filter related

    void on_lineEdit_returnPressed();   // filter related

private:
    Ui::Sniffer *ui;
    pcap_if_t *alldevs;     // all the devices
    pcap_if_t *dev;     // device
    char errbuf[PCAP_ERRBUF_SIZE];      // npcap: errbuf
    pcap_t *adhandle;       // the chosen adapter
    CapThread *capthread;       // capture thread
    int countNum;       // table widget (NO.-1)
    QVector<DataPackage>datapackage;   // store data
};
#endif // SNIFFER_H
