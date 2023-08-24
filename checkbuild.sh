#!/bin/bash

mkdir -p host-build
echo "build host version"
make -j5 -C host-build -f $(pwd)/Makefile BUILD_TARGET=$(uname) 

mkdir -p win32-build
echo "build win32 version"
# make -j5 -C win32-build -f $(pwd)/Makefile TARGET=i686-w64-mingw32 BUILD_TARGET=mingw
