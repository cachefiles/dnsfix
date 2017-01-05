MODULE := tcpup
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

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
endif

ifeq ($(BUILD_TARGET), Linux)
LOCAL_LDLIBS += -lrt
endif

LOCAL_CFLAGS += -g -Wall -Wno-sign-compare -I.
LOCAL_CXXFLAGS += -g -Wall -Wno-sign-compare -I.

VPATH := $(THIS_PATH)/libtx:$(THIS_PATH)

LOCAL_TARGETS = relaydns

all: $(LOCAL_TARGETS)
CFLAGS := $(LOCAL_CFLAGS)
CXXFLAGS := $(LOCAL_CXXFLAGS)

LDLIBS := $(LOCAL_LDLIBS)
LDFLAGS := $(LOCAL_LDFLAGS)
OBJECTS := libtx.a ncatutil.o txrelay.o txdnsxy.o txconfig.o base64.o

relaydns.exe: relaydns
	cp $< $@

relaydns: OBJECTS := $(OBJECTS)
relaydns: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

include $(THIS_PATH)/libtx/Makefile
