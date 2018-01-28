MODULE := dnsfix
THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
endif

LOCAL_CXXFLAGS := -I$(THIS_PATH)/libtx/include -I$(THIS_PATH) -D_ENABLE_INET6_
LOCAL_CFLAGS := $(LOCAL_CXXFLAGS)
LOCAL_LDLIBS := -lstdc++

ifeq ($(BUILD_TARGET), )
BUILD_TARGET:=$(shell uname)
endif

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
else
LOCAL_LDLIBS += -lresolv
endif

ifeq ($(BUILD_TARGET), Linux)
LOCAL_LDLIBS += -lrt -lresolv
endif

LOCAL_CFLAGS += -g -Wall -Wno-sign-compare -I.
LOCAL_CXXFLAGS += -g -Wall -Wno-sign-compare -I.

VPATH := $(THIS_PATH)/libtx:$(THIS_PATH)

LOCAL_TARGETS = dnsfix

all: $(LOCAL_TARGETS) stunc
CFLAGS := $(LOCAL_CFLAGS)
CXXFLAGS := $(LOCAL_CXXFLAGS)

LDLIBS := $(LOCAL_LDLIBS)
LDFLAGS := $(LOCAL_LDFLAGS)
OBJECTS := ncatutil.o txrelay.o txdnsxy.o txconfig.o base64.o dnsproto.o

dnsfix.exe: dnsfix
	cp $< $@

dnsfix: OBJECTS := $(OBJECTS)
dnsfix: $(OBJECTS) libtx.a 
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

stunc: stunutil.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

include $(THIS_PATH)/libtx/Makefile
