#!/usr/bin/env python

from scapy.all import *
import sys

if(len(sys.argv) != 2):
    print "Usage: ", sys.argv[0], "<pcap file>"
    exit()

print "packet.time system.time ip.src ip.dst"

lastPktTime=0
sentTime=0
packets = rdpcap(sys.argv[1])

for packet in packets:
    while 1:
        packetgap = packet.time - lastPktTime
        timegap = time.time() - sentTime

        if (lastPktTime == 0) or (packetgap < timegap) or (packet.time < lastPktTime):
            lastPktTime = packet.time
            sentTime = time.time()
            print packet.time, " ", time.time(), packet[IP].src, packet[IP].dst;
            send(packet[IP])
            break
        else:
            time.sleep(packetgap - timegap)
