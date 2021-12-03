#include <DataPackage.h>

DataPackage::DataPackage()
{
    this->type = 0;
    this->len = 0;
    this->timeStamp = "";
    this->pkt_data = nullptr;
}

DataPackage::~DataPackage()
{

}

void DataPackage::setLen(u_int len)
{
    this->len = len;
}

void DataPackage::setDataPointer(const u_char *pkt_data, u_int size)
{
    this->pkt_data = (u_char*)malloc(size);
    if(this->pkt_data != nullptr)
        memcpy((char*)(this->pkt_data),pkt_data,size);
    else this->pkt_data = nullptr;
}

void DataPackage::setTimStamp(QString timeStamp)
{
    this->timeStamp = timeStamp;
}

void DataPackage::setType(int type)
{
    this->type = type;
}

void DataPackage::setInfo(QString info)
{
    this->info = info;
}

QString DataPackage::getInfo()
{
    return this->info;
}

QString DataPackage::getProtocol()
{
    switch (this->type) {
    case 1:
        return "ARP";

    case 2:
        return "ICMP";

    case 3:
        return "TCP";

    case 4:
        return "UDP";

    default:
        return "Unknown protocol";
    }
}
