TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
INCLUDEPATH += $$PWD/include

SOURCES += \
        src/arp.cpp \
        src/arphdr.cpp \
        src/ethhdr.cpp \
        src/ip.cpp \
        src/iphdr.cpp \
        src/mac.cpp \
        src/main.cpp

HEADERS += \
        include/arp.h \
        include/arphdr.h \
        include/ethhdr.h \
        include/ip.h \
        include/iphdr.h \
        include/mac.h
