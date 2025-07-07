#!/usr/bin/python3
#----------------------------------------------------
# this program processes ICMP Echo Request from specified source
# and generates ICMP Echo Reply
# Sender host should received 2 ICMP Echo Reply. 
#   one from network stack, and one from this program.
#----------------------------------------------------
import sys
from scapy.all import *

if len(sys.argv) != 2:
  print("Usage: sys.argv[0] <Src IP Addr>")
  exit();

# program has all the 4 params
ip_sender = sys.argv[1]

def spoof_icmp_pkt(pkt):
  if ICMP in pkt and pkt[ICMP].type == 8:
    print("Received Pkt Details...")
    print("Src IP: ", pkt[IP].src)
    print("Dstn IP: ", pkt[IP].dst)
    # create spoof ICMP Reply 
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
    icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
    data = pkt[Raw].load
    newpkt = ip/icmp/data

    print("Spoofed Reply Pkt Details...")
    print("Src IP: ", newpkt[IP].src)
    print("Dstn IP: ", newpkt[IP].dst)
    print("#------------------")
    send(newpkt,verbose=0)

template = 'icmp and src {A}' 
cap_filter = template.format(A=ip_sender)
print("Capture Filter: ", cap_filter)
pkt = sniff(iface='eth0', filter=cap_filter, prn=spoof_icmp_pkt)

  
