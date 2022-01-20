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
    QVector<DataPackage>().swap(datapackage);
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
        ui->actionUp->setEnabled(false);
        ui->actionDown->setEnabled(false);
        ui->actionTop->setEnabled(false);
        ui->actionBottom->setEnabled(false);
        ui->comboBox->setEnabled(false);
        ui->lineEdit->setEnabled(false);

        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        countNum = 0;
        ui->treeWidget->clear();
        QVector<DataPackage>().swap(datapackage);

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
        ui->actionUp->setEnabled(true);
        ui->actionDown->setEnabled(true);
        ui->actionTop->setEnabled(true);
        ui->actionBottom->setEnabled(true);
        ui->comboBox->setEnabled(true);
        ui->lineEdit->setEnabled(true);
    });

    connect(ui->actionClear, &QAction::triggered, this, [=](){
        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        countNum = 0;
        ui->treeWidget->clear();
        QVector<DataPackage>().swap(datapackage);
    });

    connect(ui->actionUp, &QAction::triggered, this, [=](){
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(index - 1,0);
            on_tableWidget_cellClicked(index - 1,0);
        }else return;
    });

    connect(ui->actionDown, &QAction::triggered, this, [=](){
        int index = ui->tableWidget->currentRow();
        if(index >= 0 && index < ui->tableWidget->rowCount() - 1){
            ui->tableWidget->setCurrentCell(index + 1,0);
            on_tableWidget_cellClicked(index + 1,0);
        }else return;
    });

    connect(ui->actionTop, &QAction::triggered, this, [=](){
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(0,0);
            on_tableWidget_cellClicked(0,0);
        }else return;
    });

    connect(ui->actionBottom, &QAction::triggered, this, [=](){
        int index = ui->tableWidget->rowCount() - 1;
        if(index > 0){
            ui->tableWidget->setCurrentCell(index,0);
            on_tableWidget_cellClicked(index,0);
        }
    });
}

Sniffer::~Sniffer()
{
    delete ui;
    pcap_freealldevs(alldevs);
    QVector<DataPackage>().swap(datapackage);
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

// handle data
// when datapackge is emitted
void Sniffer::handleData(DataPackage data)
{
    ui->tableWidget->insertRow(countNum);
    this->datapackage.push_back(data);

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

// 设定选择行，单项选择
// 点击tableWidget中item，treeWidget中显示详细信息
void Sniffer::on_tableWidget_cellClicked(int row, int column)
{
    ui->treeWidget->clear();
    // Frame
    QString tree1 = "Frame  " + QString::number(row + 1) + ":  "
            + datapackage[row].getLen() + " bytes  captured";
    QTreeWidgetItem *item1 = new QTreeWidgetItem(QStringList()<<tree1);
    ui->treeWidget->addTopLevelItem(item1);
    item1->setBackground(0, QBrush(QColor(245, 245, 245)));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Frame Number:  " + QString::number(row + 1)));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Frame Length:  " + datapackage[row].getLen()));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Arrival Time:  " + datapackage[row].getTimeStamp()));

    // Ethernet II
    QString tree2 = "Ethernet II,  Src:  " + datapackage[row].getMacSrc()
               + ",  Dst:  " + datapackage[row].getMacDes();
    QTreeWidgetItem *item2 = new QTreeWidgetItem(QStringList()<<tree2);
    ui->treeWidget->addTopLevelItem(item2);
    item2->setBackground(0, QBrush(QColor(245, 245, 245)));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Destination:  " + datapackage[row].getMacDes()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Source:  " + datapackage[row].getMacSrc()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Type:  " + datapackage[row].getMacType()));

    // more information
    if(datapackage[row].getType() == 1){ // ARP
        showARPtree(row);
    }else{ // IPv4
        showIPtree(row);
    }
}

void Sniffer::showARPtree(int row)
{
    QString ArpType = datapackage[row].getArpOP();
    QTreeWidgetItem *item1 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol  " + ArpType);
    ui->treeWidget->addTopLevelItem(item1);
    item1->setBackground(0, QBrush(QColor(245, 245, 245)));

    QString HardwareType = datapackage[row].getArpHardwareType();
    QString protocolType = datapackage[row].getArpProtocolType();
    QString HardwareSize = datapackage[row].getArpMacLength();
    QString protocolSize = datapackage[row].getArpIpLength();
    QString srcMacAddr = datapackage[row].getArpEtherSrc();
    QString desMacAddr = datapackage[row].getArpEtherDes();
    QString srcIpAddr = datapackage[row].getArpIpSrc();
    QString desIpAddr = datapackage[row].getArpIpDes();

    item1->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:  " + HardwareType));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:  " + protocolType));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:  " + HardwareSize));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:  " + protocolSize));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:  " + ArpType));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:  " + srcMacAddr));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:  " + srcIpAddr));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:  " + desMacAddr));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:  " + desIpAddr));
    return;
}

void Sniffer::showIPtree(int row)
{
    QString srcIp = datapackage[row].getIpSrc();
    QString desIp = datapackage[row].getIpDes();

    QTreeWidgetItem*item1 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:  " + srcIp + ", Dst:  " + desIp);
    ui->treeWidget->addTopLevelItem(item1);
    item1->setBackground(0, QBrush(QColor(245, 245, 245)));

    QString version = datapackage[row].getIpVersion();
    QString headerLength = datapackage[row].getIpHeaderLength();
    QString Tos = datapackage[row].getIpTOS();
    QString totalLength = datapackage[row].getIpTotalLength();
    QString id = "0x  " + datapackage[row].getIpIdentification();
    QString flags = datapackage[row].getIpFlag();
    if(flags.size()<2)
        flags = "0" + flags;
    flags = "0x" + flags;
    QString FragmentOffset = datapackage[row].getIpOffset();
    QString ttl = datapackage[row].getIpTTL();
    QString protocol = datapackage[row].getIpProtocol();
    QString checksum = "0x" + datapackage[row].getIpChecksum();
    int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
    item1->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:  " + version));
    item1->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:  " + headerLength));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"TOS:  " + Tos));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:  " + totalLength));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Identification:  " + id));

    QString reservedBit = datapackage[row].getIpReservedBit();
    QString DF = datapackage[row].getIpDF();
    QString MF = datapackage[row].getIpMF();
    QString FLAG = ",";

    if(reservedBit == "1"){
        FLAG += "Reserved bit";
    }
    else if(DF == "1"){
        FLAG += "Don't fragment";
    }
    else if(MF == "1"){
        FLAG += "More fragment";
    }
    if(FLAG.size() == 1)
        FLAG = "";
    QTreeWidgetItem *bitTree = new QTreeWidgetItem(QStringList()<<"Flags:  " + flags + FLAG);
    item1->addChild(bitTree);
    QString temp = reservedBit == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:  " + temp));
    temp = DF == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:  " + temp));
    temp = MF == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:  " + temp));

    item1->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:  " + FragmentOffset));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:  " + ttl));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:  " + protocol));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:  " + checksum));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:  " + srcIp));
    item1->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:  " + desIp));

    switch (datapackage[row].getType()) {
    case 2: {// ICMP
        dataLengthofIp -= 8;
        QTreeWidgetItem *item2 = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
        ui->treeWidget->addTopLevelItem(item2);
        item2->setBackground(0, QBrush(QColor(245, 245, 245)));

        QString type = datapackage[row].getIcmpType();
        QString code = datapackage[row].getIcmpCode();
        QString info = ui->tableWidget->item(row,6)->text();
        QString checksum = "0x" + datapackage[row].getIcmpChecksum();
        QString id = datapackage[row].getIcmpIdentification();
        QString seq = datapackage[row].getIcmpSequence();
        item2->addChild(new QTreeWidgetItem(QStringList()<<"type:  " + type + "(" + info + ")"));
        item2->addChild(new QTreeWidgetItem(QStringList()<<"code:  " + code));
        item2->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:  " + checksum));
        item2->addChild(new QTreeWidgetItem(QStringList()<<"type:  " + type + "(" + info + ")"));
        item2->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:  " + id));
        item2->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:  " + seq));
        if(dataLengthofIp > 0){
            QTreeWidgetItem *dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
            item2->addChild(dataItem);
            QString icmpData = datapackage[row].getIcmpData(dataLengthofIp);
            dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
            dataItem->addChild(new QTreeWidgetItem(QStringList()<<"Length:  " + QString::number(dataLengthofIp)));
        }
        break;}

    case 3: {// TCP
        QString desPort = datapackage[row].getTcpDes();
        QString srcPort = datapackage[row].getTcpSrc();
        QString ack = datapackage[row].getTcpACK();
        QString seq = datapackage[row].getTcpSequence();
        QString headerLength = datapackage[row].getTcpHeaderLength();
        int rawLength = datapackage[row].getTcpRawHeaderLength().toUtf8().toInt();
        dataLengthofIp -= (rawLength * 4);
        QString dataLength = QString::number(dataLengthofIp);
        QString flag = datapackage[row].getTcpFlags();
        while(flag.size()<2)
            flag = "0" + flag;
        flag = "0x" + flag;

        QTreeWidgetItem *item3 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:  "
                                                     + srcPort + ", Dst Port:  " + desPort + ",Seq:  " + seq +
                                                     ", Ack:  " + ack + ", Len:  " + dataLength);
        ui->treeWidget->addTopLevelItem(item3);
        item3->setBackground(0, QBrush(QColor(245, 245, 245)));

        item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:  " + srcPort));
        item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:  " + desPort));
        item3->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
        item3->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


        QString sLength = QString::number(rawLength,2);
        while(sLength.size()<4)
            sLength = "0" + sLength;
        item3->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:  " + headerLength));

        QString PSH = datapackage[row].getTcpPSH();
        QString URG = datapackage[row].getTcpURG();
        QString ACK = datapackage[row].getTcpACK();
        QString RST = datapackage[row].getTcpRST();
        QString SYN = datapackage[row].getTcpSYN();
        QString FIN = datapackage[row].getTcpFIN();
        QString FLAG = "";

        if(PSH == "1")
            FLAG += "PSH,";
        if(URG == "1")
            FLAG += "UGR,";
        if(ACK == "1")
            FLAG += "ACK,";
        if(RST == "1")
            FLAG += "RST,";
        if(SYN == "1")
            FLAG += "SYN,";
        if(FIN == "1")
            FLAG += "FIN,";
        FLAG = FLAG.left(FLAG.length()-1);
        if(SYN == "1"){
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
        }
        if(SYN == "1" && ACK == "1"){
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
        }
        QTreeWidgetItem *flagTree = new QTreeWidgetItem(QStringList()<<"Flags:  " + flag + " (" + FLAG + ")");
        item3->addChild(flagTree);
        QString temp = URG == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
        temp = ACK == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
        temp = PSH == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
        temp = RST == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
        temp = SYN == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
        temp = FIN == "1"?"Set":"Not set";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

        QString window = datapackage[row].getTcpWindow();
        QString checksum = "0x" + datapackage[row].getTcpWindow();
        QString urgent = datapackage[row].getTcpUrgent();
        item3->addChild(new QTreeWidgetItem(QStringList()<<"window:  " + window));
        item3->addChild(new QTreeWidgetItem(QStringList()<<"checksum:  " + checksum));
        item3->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:  " + urgent));
        break;}

    case 4:{ // UDP
        QString srcPort = datapackage[row].getUdpSrc();
        QString desPort = datapackage[row].getUdpDes();
        QString Length = datapackage[row].getUdpDataLength();
        QString checksum = "0x" + datapackage[row].getUdpChecksum();

        QTreeWidgetItem *item4 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:  " + srcPort
                                                     + ", Dst Port:  " + desPort);
        ui->treeWidget->addTopLevelItem(item4);
        item4->setBackground(0, QBrush(QColor(245, 245, 245)));

        item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:  " + srcPort));
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:  " + desPort));
        item4->addChild(new QTreeWidgetItem(QStringList()<<"length:  " + Length));
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:  " + checksum));
        int udpLength = Length.toUtf8().toInt();
        if(udpLength > 0){
            item4->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
        }
        break;}
    default: break;
    }
}

// filter
// when text at lineEdit changed,it will check input information is correct or not
// if it is corrected,the color is green or it will be red
void Sniffer::on_lineEdit_textChanged(const QString &arg1)
{
    QString text = arg1;
    text = text.toLower();
    if(text == "" || text == "arp" || text == "icmp" || text == "tcp" || text == "udp"
            || text.startsWith("src=")|| text.startsWith("des=") || text.startsWith("addr=")){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
}

// filter
void Sniffer::on_lineEdit_returnPressed()
{
    QString text = ui->lineEdit->text();
    text = text.toUpper();
    QString target = "#";
    bool flag = false;
    int situation = 0;

    // protocol
    if(text == "" || text == "ARP" || text == "ICMP" || text == "TCP" || text == "UDP"){
        flag = true;
        situation = 1;
        target = text;
    }
    if(text.startsWith("SRC=")){
        flag = true;
        situation = 2;
        target = text.mid(4);
    }
    if(text.startsWith("DES=")){
        flag = true;
        situation = 3;
        target = text.mid(4);
    }
    if(text.startsWith("ADDR=")){
        flag = true;
        situation = 4;
        target = text.mid(5);
    }

    if(flag){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }

    int count = 0;
    int number = ui->tableWidget->rowCount();
    if(target != "#"){
        switch (situation) {
        case 1:{
            if(target!=""){
                for(int i = 0;i < number;i++){
                    if(ui->tableWidget->item(i,4)->text() != target){
                        ui->tableWidget->setRowHidden(i,true);
                    }else{
                        ui->tableWidget->setRowHidden(i,false);
                        count++;
                    }
                }
            }else{
                int number = ui->tableWidget->rowCount();
                for(int i = 0;i < number;i++){
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
            break;
        }
        case 2:{
            if(target!=""){
                for(int i = 0;i < number;i++){
                    if(ui->tableWidget->item(i,2)->text() != target){
                        ui->tableWidget->setRowHidden(i,true);
                    }else{
                        ui->tableWidget->setRowHidden(i,false);
                        count++;
                    }
                }
            }else{
                int number = ui->tableWidget->rowCount();
                for(int i = 0;i < number;i++){
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
            break;
        }
        case 3:{
            if(target!=""){
                for(int i = 0;i < number;i++){
                    if(ui->tableWidget->item(i,3)->text() != target){
                        ui->tableWidget->setRowHidden(i,true);
                    }else{
                        ui->tableWidget->setRowHidden(i,false);
                        count++;
                    }
                }
            }else{
                int number = ui->tableWidget->rowCount();
                for(int i = 0;i < number;i++){
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
            break;
        }
        case 4:{
            if(target!=""){
                for(int i = 0;i < number;i++){
                    if((ui->tableWidget->item(i,2)->text() == target)||(ui->tableWidget->item(i,3)->text() == target)){
                        ui->tableWidget->setRowHidden(i,false);
                        count++;
                    }else{
                        ui->tableWidget->setRowHidden(i,true);
                    }
                }
            }else{
                int number = ui->tableWidget->rowCount();
                for(int i = 0;i < number;i++){
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
            break;
        }
        default:;
        }
    }

    ui->treeWidget->clear();
    statusBar()->showMessage(QString::number(count) + " messages listed");
}


// filter rules
// messagebox
void Sniffer::on_actionFilter_rules_triggered()
{
    QMessageBox::about(this, "Filter rules",
                       "<center><b>合理的过滤规则</b></center>\n"
                       "<ul><li>基于协议过滤</li>"
                       "<ul><li>arp:保留ARP协议数据</li>"
                       "<li>icmp:保留ICMP协议数据</li>"
                       "<li>tcp:保留TCP协议数据</li>"
                       "<li>udp:保留UDP协议数据</li></ul>"
                       "<li>基于源/目的地址过滤</li>"
                       "<ul><li>src={source}:源地址为{source}</li>"
                       "<li>des={destination}:目的地址为{destination}</li>"
                       "<li>addr={source/destination}:源地址为{source}或目的地址为{destination}</li></ul></ul>"
                       "\n"
                       "(过滤规则不区分大小写且规则内不能含有空格)");
}

// about us
void Sniffer::on_actionAbout_us_triggered()
{
    QMessageBox::about(this, tr("About us"),
                 tr("<center><b>2021计网大作业</b></center>\n"
                    "<center><b>——基于Pcap的网络嗅探器</b></center>\n"
                    "<center>小组成员：章杭炜，李佳露</center>"));
}

