#!/bin/bash

C=$(od -An --endian=big -d -N 2)
C=${C//[[:blank:]]/}
URL=https://www.cootail.com/dns_query/ 
# URL=https://one.one.one.one/dns-query
# (dd bs=$C count=1 status=none) | curl -H "Content-Type: application/dns-message" -H "Content-Length: $C" --data-binary @- $URL > /tmp/dns.data
curl -v -H "Content-Type: application/dns-message" -H "Content-Length: $C"  --data-binary @<(dd bs=$C count=1 status=none) $URL > /tmp/dns.data
printf "00: 00 %02x" $(wc -c < /tmp/dns.data) |xxd -r
cat /tmp/dns.data
