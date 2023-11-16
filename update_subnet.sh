#!/bin/bash

test -f delegated-apnic-latest || wget -4 https://ftp.apnic.net/stats/apnic/delegated-apnic-latest

grep "[A-Z][A-Z]|ipv4|" delegated-apnic-latest |grep -v CN|awk -F '|' '{print $4 "/" $5;}' > list-ipv4-without-cn.txt
grep "[A-Z][A-Z]|ipv6|" delegated-apnic-latest |grep -v CN|awk -F '|' '{print $4 "/" $5;}' > list-ipv6-without-cn.txt

./subnet_gen -4 -i list-ipv4-without-cn.txt > subnet_data.c
./subnet_gen -6 -i list-ipv6-without-cn.txt >> subnet_data.c

grep "[A-Z][A-Z]|ipv4|" delegated-apnic-latest |grep CN|awk -F '|' '{print $4 "/" $5;}' > list-ipv4-cn.txt
grep "[A-Z][A-Z]|ipv6|" delegated-apnic-latest |grep CN|awk -F '|' '{print $4 "/" $5;}' > list-ipv6-cn.txt

test -f ./subnet_gen && ./subnet_gen -4 -t -e list-ipv4-cn.txt > subnet_xdata.c
test -f ./subnet_gen && ./subnet_gen -6 -t -e list-ipv6-cn.txt >> subnet_xdata.c
