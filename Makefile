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

LOCAL_TARGETS = dns_lookup dnsfixd

.PHONY: all
all: $(LOCAL_TARGETS) stunc dns_res_trd dns_mod_trd dns_mod_gfw dns_echo dns_resolver_ng
CFLAGS := $(LOCAL_CFLAGS)
CXXFLAGS := $(LOCAL_CXXFLAGS)

LDLIBS := $(LOCAL_LDLIBS)
LDFLAGS := $(LOCAL_LDFLAGS)
OBJECTS := ncatutil.o dnsproto.o router.o subnet_data.o subnet_api.o

dns_mod_trd: dns_mod_trd.o dnsproto.o subnet_api.o subnet_data.o
	$(CC) $(LDFLAGS) -o $@ $^ -lresolv 

dns_resolver_ng: dns_resolver_ng.o dnsproto.o subnet_api.o subnet_data.o tx_debug.o
	$(CC) $(LDFLAGS) -o $@ $^ -lresolv

dns_mod_gfw: dns_mod_gfw.o subnet_api.o subnet_data.o dnsproto.o tx_debug.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

dns_echo: dns_echo.o tx_debug.o
	$(CC) $(LDFLAGS) -o $@ $^ -lresolv

dns_res_trd: dns_res_trd.o dnsproto.o subnet_api.o subnet_data.o
	$(CC) $(LDFLAGS) -o $@ $^ -lresolv

dns_lookup: dns_lookup.o dnsproto.o subnet_api.o subnet_data.o
	$(CC) $(LDFLAGS) -o $@ $^ -lresolv

dnsfixd: dns_fixd.o dnsproto.o subnet_api.o subnet_data.o libtx.a
	$(CC) $(LDFLAGS) -o $@ $^  $(LDLIBS)

dnsfix.exe: dnsfix
	cp $< $@

dnsfix: OBJECTS := $(OBJECTS)
dnsfix: $(OBJECTS) libtx.a 
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

stunc: stunutil.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

subnet_gen: subnet_gen.o subnet_api.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

include $(THIS_PATH)/libtx/Makefile
