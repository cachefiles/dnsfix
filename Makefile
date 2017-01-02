RMR ?=rm -f
RANLIB ?=ranlib

LDLIBS += -lstdc++
CFLAGS += -Ilibtx/include -D_ENABLE_INET6_
CXXFLAGS += $(CFLAGS)

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
endif

BUILD_TARGET := "UNKOWN"

ifeq ($(LOGNAME),)
BUILD_TARGET := "mingw"
else
BUILD_TARGET := $(findstring mingw, $(CC))
endif

ifeq ($(BUILD_TARGET),)
BUILD_TARGET := $(shell uname)
endif

ifeq ($(BUILD_TARGET), mingw)
TARGETS = txrelay.exe
LDLIBS += -lws2_32
else
TARGETS = txrelay
endif

ifeq ($(BUILD_TARGET), Linux)
LDLIBS += -lrt
endif

OBJECTS = libtx.a
XCLEANS = txcat.o ncatutil.o txrelay.o txdnsxy.o txconfig.o base64.o
VPATH  += libtx

all: $(TARGETS)

libtx/libtx.a:
	make -C libtx

txrelay.exe: txrelay.o base64.o ncatutil.o txdnsxy.o txconfig.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o txrelay.exe $^ $(LDLIBS)

txrelay: txrelay.o base64.o txdnsxy.o txconfig.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o txrelay.exe $^ $(LDLIBS)

.PHONY: clean

clean:
	$(RM) $(OBJECTS) $(TARGETS) $(XCLEANS)

