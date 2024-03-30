#!/usr/bin/env python3
from scapy.all import *
import argparse
from scapy.layers import http

def process_packet(packet):   
    if packet.haslayer(http.HTTPRequest):
        print("[+] IP src: ",packet[IP].src)
        print("[+] IP dst: ",packet[IP].dst)
        print("[+] protocol :", packet[http.HTTPRequest].Http_Version.decode())
        print("[+] Type: ", packet[http.HTTPRequest].Method.decode())
        print("[+] Host: ", packet[http.HTTPRequest].Host.decode())
        print("[+] Accept_Language: ", packet[http.HTTPRequest].Accept_Language.decode()) 
        print("[+] Accept:", packet[http.HTTPRequest].Accept.decode())   
        print("[+] Accept-Encoding: ", packet[http.HTTPRequest].Accept_Encoding.decode())  
        # Print payload
        print("[+] Payload: ", packet[http.HTTPRequest].payload.decode())             
        print("----"*20)

sniff(iface='eth0', prn=process_packet, store=0)

