#!/bin/env python3
import socks
import sys

proxy_server = sys.argv[1]
proxy_port = int(sys.argv[2])
web_server = sys.argv[3]
web_port = int(sys.argv[4])

s = socks.socksocket()

# Set the proxy
s.set_proxy(socks.SOCKS5, proxy_server, proxy_port) 

# Connect to final destination via the proxy
s.connect((web_server, web_port))

request = b"GET /welcome.html HTTP/1.0\r\nHost: " + web_server.encode('utf-8') + b"\r\n\r\n"
s.sendall(request)

# Get the response
response = s.recv(2048)
while response:
  print(response.split(b"\r\n"))
  response = s.recv(2048)
