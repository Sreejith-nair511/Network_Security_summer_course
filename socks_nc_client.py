#!/bin/env python3
import socket, socks, sys

# get proxy server details
proxy_host = sys.argv[1] 
proxy_port = int(sys.argv[2])

# Netcat server settings
server_host = sys.argv[3]  
server_port = int(sys.argv[4])

# Set up a SOCKS5 proxy connection
socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
socket.socket = socks.socksocket

# Create a socket to connect to the Netcat server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((server_host, server_port))
            
    # Send message 
    msg = "Socks5 netcat client\r\n"
    s.sendall(msg.encode())
    print("Sent to server: {}".format(msg))

    resp = s.recv(1024)
    print("Received from server: {}".format(resp.decode()))
