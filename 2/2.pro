QT += core
QT -= gui

CONFIG += c++11

TARGET = 1
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
TEMPLATE = app
LIBS += -lpcap
SOURCES += main.cpp
