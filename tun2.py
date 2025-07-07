#!/usr/bin/env python3
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.88/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
   # get the pkt from tun interface
   packet = os.read(tun, 2048)
   if packet:
     pkt = IP(packet)
     print(pkt.summary())

     # send a spoof pkt using tun interface
     if ICMP in pkt:
       newip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl, ttl=99)
       newicmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
       if pkt.haslayer(Raw):
         data = pkt[Raw].load
         newpkt = newip/newicmp/data
       else:
         newpkt = newip/newicmp

       os.write(tun, bytes(newpkt))
