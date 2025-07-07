#!/usr/bin/python3
# this program simply captures ICMP packets and prints these
# -------------------------------
import sys
from scapy.all import *


def print_pkt(pkt):
  print(pkt.summary())

pkt = sniff(iface='eth0', filter='icmp', prn=print_pkt)

  
