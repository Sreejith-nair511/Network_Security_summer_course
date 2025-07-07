#!/usr/bin/python3
# this program simply spoofs a ICMP with different src IP
# Assuming this program runs on A (172.21.0.11) and spoofs with following
# src IP=172.21.0.12 (host B) with destination of 172.21.0.13 (host C)
# -------------------------------
import sys
from scapy.all import *

if len(sys.argv) != 3:
  print("Usage: sys.argv[0] <IP address of spoof src> <IP address of destination>")
  exit()

ip = IP(src=sys.argv[1], dst=sys.argv[2])
icmp = ICMP()
pkt = ip/icmp
pkt.show()
send(pkt,verbose=0)
