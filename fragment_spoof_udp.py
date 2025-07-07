#!/usr/bin/python3
# this program simply spoofs a UDP with fragmentation
# -------------------------------
import sys
from scapy.all import *
import time

if len(sys.argv) != 4:
  print("Usage: sys.argv[0] <dst IP> <dst port> <delay>")
  exit()

delay = int(sys.argv[3])
ID = 32768
ip = IP(dst=sys.argv[1], id=ID, frag=0, flags=1) # set M-bit=1
udp = UDP(dport=int(sys.argv[2]), chksum=0)

udp.len = 8 + 72 + 80 + 20
data = "A" * 71 + "\n"
pktfrag1 = ip/udp/data

# offset = (8+72)/8=10
ip = IP(dst=sys.argv[1], id=ID, frag=10, flags=1) # set M-bit=1
ip.proto = 17 #UDP
payload2 = "B" * 79 + "\n"
pktfrag2 = ip/payload2

# offset = (8+72+80)/8=20
ip = IP(dst=sys.argv[1], id=ID, frag=20, flags=0) # set M-bit=0
ip.proto = 17 #UDP
payload3 = "C" * 19 + "\n"
pktfrag3 = ip/payload3

# sending fragments
print("sending Fragment 3")
send(pktfrag3)
print("sending Fragment 1 after " + str(delay) + " s")
time.sleep(delay)
send(pktfrag1)
print("sending Fragment 2 after " + str(2*delay) + " s")
time.sleep(2*delay)
send(pktfrag2)

