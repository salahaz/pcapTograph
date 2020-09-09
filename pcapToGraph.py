import re
from scapy.all import *
from collections import OrderedDict
from py2neo import Graph, Node, Relationship


# Returns all protocols of the packet
def get_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        packet_info = packet.show(dump=True)

        if layer is None:
            break

        if layer.name == "IP" and re.search("IPv4", packet_info):
            yield "IPv4"
        elif layer.name == "IP" and re.search("IPv6", packet_info):
            yield "IPv6"

        if layer.name == "Raw":
            if re.search("ssdp", packet_info):
                yield "SSDP"
            elif re.search("http\n", packet_info):
                yield "HTTP"
            elif re.search("https\n", packet_info):
                yield "HTTPS"
            elif re.search("nat_pmp", packet_info):
                yield "NAT Port"
            elif re.search("icmp", packet_info):
                yield "ICMP"
            elif re.search("ARP", packet_info):
                yield "ARP"

        elif layer.name != "IP" and layer.name != "Padding":
            yield layer.name

        counter += 1


# Reading PCAP file and accessing graph
packets = rdpcap("smallFlows.pcap")


g = Graph(password="@csc3350@")

# Creating nodes, their relationships
# and adding them to the graph
for packet in packets:
    layers = []
    try:
        a = Node("Host", name=packet.getlayer(IP).src)
        b = Node("Host", name=packet.getlayer(IP).dst)
    except AttributeError:
        a = Node("Host", name=packet.getlayer(ARP).psrc)
        b = Node("Host", name=packet.getlayer(ARP).pdst)

    for layer in get_layers(packet):
        layers.append(layer)

    protocols = ':'.join(layers)
    relation = Relationship.type(':'.join(OrderedDict.fromkeys(protocols.split(':'))))
    g.merge(relation(a, b), "Host", "name")
