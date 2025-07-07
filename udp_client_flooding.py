#!/usr/bin/python3
import socket
from scapy.all import *

ip = IP(src="172.21.4.5", dst="172.21.5.5")
udp = UDP(sport=9999, dport=9999)
data = "The ping pong game\n"

pkt = ip/udp/data
while True:
  send(pkt, verbose=0)
