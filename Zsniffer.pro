QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    CapThread.cpp \
    DataPackage.cpp \
    Sniffer.cpp \
    main.cpp

HEADERS += \
    CapThread.h \
    DataPackage.h \
    HeaderInfo.h \
    Sniffer.h

FORMS += \
    Sniffer.ui

INCLUDEPATH += D:\QtProject\Zsniffer_test\npcap-sdk-1.11\Include
LIBS += D:\QtProject\Zsniffer_test\npcap-sdk-1.11\Lib\x64\wpcap.lib
LIBS += D:\QtProject\Zsniffer_test\npcap-sdk-1.11\Lib\x64\Packet.lib
LIBS += D:\QtProject\Zsniffer_test\npcap-sdk-1.11\Lib\wpcap.lib
LIBS += D:\QtProject\Zsniffer_test\npcap-sdk-1.11\Lib\Packet.lib
LIBS += -lws2_32

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    src.qrc
