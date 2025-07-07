#!/usr/bin/python3
import socket
import time
import datetime
import argparse

parser = argparse.ArgumentParser(description="Simple Server for N/w Delays")
parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
parser.add_argument('-p', '--port', type=int, default=9999)
parser.add_argument('-d', '--delay',  type=int, default=0)
parser.add_argument('-b', '--buffer',  type=int, default=512)
args = parser.parse_args()

ip_addr = args.server
port = args.port
delay = args.delay
buffer = args.buffer

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srvr_addr = (ip_addr, port)
sock.bind(srvr_addr)

cnt = 1
while True:
  data, (cip, cport) = sock.recvfrom(buffer)
  print(datetime.datetime.now(), end=": ")
  print("cnt={}, C IP:{}, C Port:{}, data: {}".format(cnt, cip, cport, data.decode()))
  time.sleep(delay)
  sock.sendto(b'Thank You!', (cip, cport))
  cnt = cnt + 1

