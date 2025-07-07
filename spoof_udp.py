#!/usr/bin/python3
# this program simply spoofs a UDP with different src IP
# -------------------------------
import sys
from scapy.all import *

if len(sys.argv) != 5:
  print("Usage: sys.argv[0] <src IP src> <src port > <dst IP> <dst port>")
  exit()

ip = IP(src=sys.argv[1], dst=sys.argv[3])
udp = UDP(sport=int(sys.argv[2]), dport=int(sys.argv[4]))

data = "Spoofed UDP packet\n"
pkt = ip/udp/data
pkt.show()
send(pkt,verbose=0)
