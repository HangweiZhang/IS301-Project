#include "Sniffer.h"
#include "ui_Sniffer.h"

Sniffer::Sniffer(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::Sniffer)
{
    ui->setupUi(this);
    ui->statusbar->showMessage("Welcome to ZLsniffer!");

    // initialization
    dev = nullptr;
    adhandle = nullptr;
    capthread = nullptr;
    countNum = 0;
    ui->tableWidget->setColumnWidth(2, 200);
    ui->tableWidget->setColumnWidth(3, 200);

    // show the network card
    showNetworkCard();

    // functions
    connect(ui->actionStart, &QAction::triggered, this, [=](){
        int res = -1;
        res = openAdapter();
        if(res == 0){
            capthread = new CapThread(adhandle);
            capthread->setFlag();
            capthread->start();
        }

        ui->actionStart->setEnabled(false);
        ui->actionStop->setEnabled(true);
        ui->actionClear->setEnabled(false);
        ui->comboBox->setEnabled(false);

        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        countNum = 0;

        connect(capthread, &CapThread::sendData, this, &Sniffer::handleData);
    });

    connect(ui->actionStop, &QAction::triggered, this, [=](){
        if(capthread && capthread->isRunning()){
            capthread->setFlag();
            capthread->quit();
            capthread = nullptr;
        }

        if(adhandle){
            pcap_close(adhandle);
            adhandle = nullptr;
        }

        ui->actionStart->setEnabled(true);
        ui->actionStop->setEnabled(false);
        ui->actionClear->setEnabled(true);
        ui->comboBox->setEnabled(true);
    });

    connect(ui->actionClear, &QAction::triggered, this, [=](){
        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        countNum = 0;
    });
}

Sniffer::~Sniffer()
{
    delete ui;
    pcap_freealldevs(alldevs);
}

// show the available network card
void Sniffer::showNetworkCard()
{
    int i = 0;
    ui->comboBox->clear();

    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
        ui->statusbar->showMessage("There is something wrong" + QString(errbuf));
        ui->comboBox->addItem("Cannot find a matching network card.");
        return;
    }

    ui->comboBox->addItem("please chose the Network Card first!");

    for(dev = alldevs; dev != nullptr; dev = dev->next){
        QString device_name = dev->name;
        device_name.replace("rpcap://\\Device\\", "Device: ");
        i++;
        if (dev->description){
            QString device_description = dev->description;
            device_description.replace(" '", ": ");
            ui->comboBox->addItem(device_name + "   " + device_description);
        }
        else{
            ui->comboBox->addItem(device_name + "   No description available");
        }
    }
    if(i == 0){
        ui->comboBox->addItem("Cannot find a matching network card.");
    }
}

// choose the device
// according to the item's index
void Sniffer::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0){
        for(dev = alldevs, i=0; i< index - 1 ; dev = dev->next, i++);
    }else{
        dev = nullptr;
    }
}

// open the adapter
// return 0: succeed
// return -1: failed
// works only on Ethernet networks
int Sniffer::openAdapter(){
    if(dev){
        adhandle= pcap_open(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    }else{
        ui->statusbar->showMessage("Please choose the network card first!");
        return -1;
    }

    if(!adhandle){
        QString device_name = dev->name;
        device_name.replace("rpcap://\\Device\\", "");
        ui->statusbar->showMessage("Unable to open the adapter " + device_name);
        return -1;
    }

    if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
            pcap_close(adhandle);
            ui->statusbar->showMessage("This program works only on Ethernet networks.");
            return -1;
        }

    QString device_description = dev->description;
    device_description.replace(" '", ": ");
    ui->statusbar->showMessage(device_description);
    return 0;
}

void Sniffer::handleData(DataPackage data)
{
    ui->tableWidget->insertRow(countNum);

    ui->tableWidget->setItem(countNum, 0, new QTableWidgetItem(QString::number(countNum+1)));
    ui->tableWidget->setItem(countNum, 1, new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNum, 2, new QTableWidgetItem(data.getSrc()));
    ui->tableWidget->setItem(countNum, 3, new QTableWidgetItem(data.getDes()));
    ui->tableWidget->setItem(countNum, 4, new QTableWidgetItem(data.getProtocol()));
    ui->tableWidget->setItem(countNum, 5, new QTableWidgetItem(data.getLen()));
    ui->tableWidget->setItem(countNum, 6, new QTableWidgetItem(data.getInfo()));

    int type = data.getType();
    QColor color;

    switch (type) {
    case 1 : // ARP
        color = QColor(255, 228, 225);
        break;
    case 2 : // ICMP
        color = QColor(255, 250, 205);
        break;
    case 3 : // TCP
        color = QColor(220, 248, 255);
        break;
    case 4 : // UDP
        color = QColor(240, 238, 255);
        break;
    default:
        color = QColor(220, 220, 220);
    }

    for(int i = 0; i < 7; i++){
        ui->tableWidget->item(countNum,i)->setBackground(color);
    }

    countNum++;
}
