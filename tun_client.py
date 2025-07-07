#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import sys
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

SERVER_ADDR = sys.argv[1]
SERVER_PORT = int(sys.argv[2])

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.88/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# create a UDP Packet
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
   # get the pkt from tun interface
   packet = os.read(tun, 2048)
   if packet:
     pkt = IP(packet)
     print(pkt.summary())

     # send the packet via tunnel
     sock.sendto(packet, (SERVER_ADDR, SERVER_PORT))

