#!/usr/bin/env python
import os
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_if():
    ifs=get_if_list()
    iface=None
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

def send_ack(pkt):
    iface = get_if()
    ack = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
    ack = ack / IP(dst=pkt[IP].src, proto=17) / UDP(dport=4322, sport=1235) / MRI(count=pkt[MRI].count, swtraces=pkt[MRI].swtraces)
    ack.show2()
    sendp(ack, iface=iface, verbose=False)
    print ("ACK sent")    

def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
    sys.stdout.flush()
    send_ack(pkt)

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
