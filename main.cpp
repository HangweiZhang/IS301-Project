#include "Sniffer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Sniffer s;
    s.setWindowTitle("ZLsniffer - @copyright by Z/L 2021");
    s.show();
    return a.exec();
}
