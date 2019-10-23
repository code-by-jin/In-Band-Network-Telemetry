#!/usr/bin/env python
import os
import sys
import struct
import pandas as pd

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


#def record_int(pkt):
#    file_name = "int_data.csv"    
#    df = pd.DataFrame()
#    for i in range(len(pkt.options[0].swtraces)):
#        swid = str(pkt.options[0].swtraces[i].swid)
#        df[swid] = [pkt.options[0].swtraces[i].qlatency]
#
#    if os.path.exists(file_name):
#        df_exist = pd.read_csv(file_name)
#        df = pd.concat([df_exist, df])
#
#    df.to_csv (file_name, index = None, header=True)


def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
    #record_int(pkt)
    sys.stdout.flush()

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]
class SourceRoutingTail(Packet):
   fields_desc = [ XShortField("etherType", 0x800)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, SourceRoutingTail, bos=1)
bind_layers(SourceRoutingTail, MRI)

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
