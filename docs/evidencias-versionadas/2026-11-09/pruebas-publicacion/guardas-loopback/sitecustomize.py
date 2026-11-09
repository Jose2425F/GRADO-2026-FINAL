import socket,ipaddress,os
from pathlib import Path
def allowed(host):
 if host is None or host in ("localhost", ""): return True
 try:return ipaddress.ip_address(str(host).split("%",1)[0]).is_loopback
 except ValueError:return False
def reject(host):
 log=os.environ.get("TEST_NETWORK_GUARD_LOG")
 if log:
  with open(log,"a") as f:f.write("blocked connection outside loopback: "+str(host)+"\n")
 raise OSError("validation guard blocked a connection outside loopback")
_orig_connect=socket.socket.connect
_orig_connect_ex=socket.socket.connect_ex
_orig_getaddrinfo=socket.getaddrinfo
def connect(s,address):
 if s.family in (socket.AF_INET,socket.AF_INET6) and not allowed(address[0]):reject(address[0])
 return _orig_connect(s,address)
def connect_ex(s,address):
 if s.family in (socket.AF_INET,socket.AF_INET6) and not allowed(address[0]):reject(address[0])
 return _orig_connect_ex(s,address)
def getaddrinfo(host,*args,**kwargs):
 if not allowed(host):reject(host)
 return _orig_getaddrinfo(host,*args,**kwargs)
socket.socket.connect=connect
socket.socket.connect_ex=connect_ex
socket.getaddrinfo=getaddrinfo
