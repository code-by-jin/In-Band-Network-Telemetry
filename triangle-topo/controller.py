import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeTraceRules(p4info_helper, sw):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid": sw.device_id,
        })
    sw.WriteTableEntry(table_entry)
    print "Installed swtrace rule on %s" % sw.name

def writeIpv4Rules(p4info_helper, sw, dst_eth_addr, dst_ip_addr, egress_port):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": egress_port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

def readTableRules(p4info_helper, sw):
    
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='../logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='../logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='../logs/s3-p4runtime-requests.txt')

        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        for s in [s1, s2, s3]:
            s.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on %s" % s.name
       
        # Write rules for tracing the traffic
        for s in [s1, s2, s3]:
            writeTraceRules(p4info_helper, sw=s)
        
        # Write rules for forward the traffic to h1
        h1_ip_addr="10.0.1.1"
        writeIpv4Rules(p4info_helper, s1, dst_eth_addr="08:00:00:00:01:11", dst_ip_addr=h1_ip_addr, egress_port=1)   
        writeIpv4Rules(p4info_helper, s2, dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=h1_ip_addr, egress_port=2)  
        writeIpv4Rules(p4info_helper, s3, dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=h1_ip_addr, egress_port=2)  

        h2_ip_addr="10.0.2.2"
        writeIpv4Rules(p4info_helper, s1, dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=h2_ip_addr, egress_port=2)   
        writeIpv4Rules(p4info_helper, s2, dst_eth_addr="08:00:00:00:02:22", dst_ip_addr=h2_ip_addr, egress_port=1) 
        writeIpv4Rules(p4info_helper, s3, dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=h2_ip_addr, egress_port=3) 

        h3_ip_addr="10.0.3.3"
        writeIpv4Rules(p4info_helper, s1, dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=h3_ip_addr, egress_port=3) 
        writeIpv4Rules(p4info_helper, s2, dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=h3_ip_addr, egress_port=3)
        writeIpv4Rules(p4info_helper, s3, dst_eth_addr="08:00:00:00:03:33", dst_ip_addr=h3_ip_addr, egress_port=1)

        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../build/app.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='../build/app.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)

