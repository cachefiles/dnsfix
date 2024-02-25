#!/bin/bash

C=$(od -An --endian=big -d -N 2)
C=${C//[[:blank:]]/}
URL=https://blocked.cootail.com/dns-query
# URL=https://one.one.one.one/dns-query
# (dd bs=$C count=1 status=none) | curl -H "Content-Type: application/dns-message" -H "Content-Length: $C" --data-binary @- $URL > /tmp/dns.data

rm /tmp/dns.data
curl  -H "Content-Type: application/dns-message" -H "Content-Length: $C"  --data-binary @<(dd bs=$C count=1 status=none) $URL > /tmp/dns.data

L=$(wc -c < /tmp/dns.data)
printf "00: %02x %02x\n" $(($L/256)) $(($L%256)) | xxd -r

cat /tmp/dns.data
