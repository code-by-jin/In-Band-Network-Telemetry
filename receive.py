#!/usr/bin/env python
import os
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
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


class Agri(Packet):
    fields_desc = [ IntField("id", 0),
                  LongField("pH", 0),
                  LongField("temp", 0)]

def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
    sys.stdout.flush()

bind_layers(Ether, IP)
bind_layers(IP, Agri)

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(flter="ip", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
