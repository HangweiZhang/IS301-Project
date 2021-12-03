#include "Sniffer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Sniffer s;
    s.setWindowTitle("Zsniffer - @copyright by ZHW 2021");
    s.show();
    return a.exec();
}
