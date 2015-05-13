#!/usr/bin/env python

from scapy.all import *
import sys

if(len(sys.argv) != 2):
    print "Usage: ", sys.argv[0], "<pcap file>"
    exit()

lastPktTime=0
sentTime=0
packets = rdpcap(sys.argv[1])

with open('.timedreplay', 'r') as x:
    config = x.readlines()

for line in config:
    exec(line)

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
