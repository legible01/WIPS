TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    listload.cpp \
    packframes.cpp \
    usrfunc.cpp \
    pktpassway.cpp \
    devsearch.cpp \
    dbmanage.cpp \
    main.cpp \
    mac.cpp \
    deauth.cpp


HEADERS += \
    listload.h \
    packframes.h \
    usrfunc.h \
    pktpassway.h \
    devsearch.h \
    dbmanage.h \
    mac.h \
    deauth.h \
    aaa.h \
    wonsang.h \
    bbb.h
LIBS += -lpcap
LIBS +=-lmysqlclient



