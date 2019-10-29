#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
# import pandas as pd
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
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

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
# bind_layers(IP, MRI)
bind_layers(IP, UDP)
bind_layers(UDP, MRI)

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: "<message>"'
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    while True:
        #df = pd.read_csv('int_data.csv')
        print
        s = str(raw_input('Type space separated port nums '
                          '(example: "2 3 1") or "q" to quit: '))
        if s == "q":
            break;
        print
    
        i = 0
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") 
        for p in s.split(" "):
            try:
                pkt = pkt / SourceRoute(bos=0, port=int(p))
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, i).bos = 1
        pkt.show2()
        pkt = pkt / IP(dst=addr, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=0, swtraces=[]) / sys.argv[2]

        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
