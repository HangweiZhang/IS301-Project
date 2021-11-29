#include "sniffer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    sniffer w;
    w.setWindowTitle("Zsniffer");
    w.show();
    return a.exec();
}
