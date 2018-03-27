TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    listload.cpp \
    pktpassway.cpp

HEADERS += \
    pktpassway.h \
    listload.h

LIBS += -lpcap
