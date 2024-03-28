import scapy.all as scapy
from scapy.layers import http

def sniffing(interface):
     scapy.sniff(iface=interface, store=False,prn=print_packets)

def print_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet[http.HTTPRequest].Host)
       print(packet.show())


sniffing('Wi-Fi 3')