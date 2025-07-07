#!/usr/bin/env python3

from scapy.all import *

IP_ADDR = "0.0.0.0"
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_ADDR, PORT))

while True:
  data, (ip, port) = sock.recvfrom(2048)
  print("{}:{} --> {}:{}".format(ip, port, IP_ADDR, PORT))
  pkt = IP(data)
  print("*** Inside pkt: {}-->{}".format(pkt.src, pkt.dst))

