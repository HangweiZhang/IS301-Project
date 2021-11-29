#include "sniffer.h"
#include "ui_sniffer.h"

sniffer::sniffer(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::sniffer)
{
    ui->setupUi(this);
    ui->statusbar->showMessage("Welcome to Zsniffer!");

    // show the network card
    showNetworkCard();

    // initialization
    dev = nullptr;
    adhandle = nullptr;

    // functions
    connect(ui->actionStart, &QAction::triggered, this, &sniffer::openAdapter);
}

sniffer::~sniffer()
{
    delete ui;
}

// show the available network card
void sniffer::showNetworkCard()
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
void sniffer::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0){
        for(dev = alldevs, i=0; i< index - 1 ; dev = dev->next, i++);
    }else{
        dev = nullptr;
    }
}

// open the adapter
// return 0: succeed;
// return -1: failed;
int sniffer::openAdapter(){
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
        pcap_freealldevs(alldevs);
        return -1;
    }

    QString device_description = dev->description;
    device_description.replace(" '", ": ");
    ui->statusbar->showMessage(device_description);
    return 0;
}

