#include "CapThread.h"

CapThread::CapThread(pcap_t *adhandle)
{
    this->adhandle = adhandle;
}

void CapThread::run()
{
    int res;
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
        {

            if(res == 0)
                /* 超时时间到 */
                continue;

            /* 将时间戳转换成可识别的格式 */
            local_tv_sec = header->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
            qDebug() << timestr;
        }

        if(res == -1)
        {
            qDebug() << "Error reading the packets" ;

        }
}
