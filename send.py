#!/usr/bin/env python

from multiprocessing import Process
import argparse
import sys
import socket
import random
import struct

from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *

from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                    IntField("qdepth", 0),
                    IntField("qlatency", 0),
                    IntField("plength", 0)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
   fields_desc = [ ShortField("count", 0),
                   PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1))]

bind_layers(UDP, MRI)

def send():
    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<num>"'
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    iface_tx = get_if()
    pkt = Ether(src=get_if_hwaddr(iface_tx), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=0, swtraces=[]) / str(RandString(size=1000))
    pkt.show2()
    global window
    for i in range(0, int(sys.argv[2])):
        sendp(pkt, iface=iface_tx, verbose=False)

dict_mri = {}

def handle_pkt(ack):
    print "[!] Got New Packet: {src} -> {dst}".format(src=ack[IP].src, dst=ack[IP].dst)
    ack.show2()
    sys.stdout.flush()
    global dict_mri
    global count
    for i in range(0, len(ack[MRI].swtraces)): 
        dict_mri[ack[MRI].swtraces[i].swid] = ack[MRI].swtraces[i].qdepth  
    print dict_mri
    

def receive():    
    iface_rx = 'eth0'
    print "sniffing on %s" % iface_rx
    sys.stdout.flush()
    sniff(filter="udp and port 4322", iface = iface_rx,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    
    Process(target = send).start()
    Process(target = receive).start()
