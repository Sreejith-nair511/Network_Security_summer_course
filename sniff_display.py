#!/usr/bin/python3
# this program simply captures ICMP packets and prints these
# -------------------------------
import sys
from scapy.all import *


pkts = sniff(iface='eth0', filter='icmp', count=2)
print("----------------------")
hexdump(pkts[0])
print("----------------------")
ls(pkts[0])
print("----------------------")
pkts[0].summary()
print("----------------------")
pkts[0].show()

  
