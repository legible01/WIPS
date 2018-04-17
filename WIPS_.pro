TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    listload.cpp \
    pktpassway.cpp \
    devsearch.cpp \
    dbmanage.cpp \
    main.cpp \
    mac.cpp

HEADERS += \
    pktpassway.h \
    listload.h \
    devsearch.h \
    dbmanage.h \
    mac.h

LIBS += -lpcap
LIBS +=-lmysqlclient



