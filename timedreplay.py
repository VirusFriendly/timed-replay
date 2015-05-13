#!/usr/bin/env python

from scapy.all import *
import sys

if(len(sys.argv) != 2):
    print "Usage: ", sys.argv[0], "<pcap file>"
    exit()

lastPktTime=0
sentTime=0
packets = rdpcap(sys.argv[1])
# read host IPs and interfaces from config file
# hostA 1.0.0.5 eth1
# hostB 2.0.0.5 eth2
# etc...

for packet in packets:
    while 1:
        packetgap = packet.time - lastPktTime
        timegap = time.time() - sentTime

        if (lastPktTime == 0) or (packetgap < timegap) or (packet.time < lastPktTime):
            lastPktTime = packet.time
            sentTime = time.time()
            # match the packet source to interface via config
            # send packet via sendp()
            print packet.time, " ", time.time();
            break
        else:
            time.sleep(packetgap - timegap)
