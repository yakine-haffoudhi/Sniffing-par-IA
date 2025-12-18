import torch
from scapy.all import sniff, wrpcap, rdpcap, get_if_list, IP, TCP, UDP, ICMP, IPv6
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP

#print(get_if_list())
#paquet = sniff(iface="Wi-Fi", filter="tcp", count=10)
#wrpcap("test.cap", paquet)
PaquetImport = rdpcap("donnees_short.pcap")

print(len(PaquetImport))
pkt = PaquetImport[10]
print(pkt)
print(pkt.time)           # Horodatage

# Affichage MAC source/dest si possible
if pkt.haslayer("Ether"):
    print(pkt["Ether"].src, pkt["Ether"].dst)
elif pkt.haslayer("CookedLinux"):
    mac_src = getattr(pkt["CookedLinux"], "src", None)
    mac_dst = getattr(pkt["CookedLinux"], "dst", None)
    print(mac_src, mac_dst)
else:
    print("Pas de couche MAC identifiable")

print(len(pkt))   # MAC source/dest (Ether)

if IP in pkt:
    print(pkt[IP].src)        # IP source
    print(pkt[IP].dst)        # IP destination
elif IPv6 in pkt:
    print(pkt[IPv6].src)      # IPv6 source
    print(pkt[IPv6].dst)      # IPv6 destination

if TCP in pkt:
    print("Protocole : TCP")
    print(pkt[TCP].sport, pkt[TCP].dport)
elif UDP in pkt:
    print("Protocole : UDP")
    print(pkt[UDP].sport, pkt[UDP].dport)
elif ICMP in pkt:
    print("Protocole : ICMP")
    print(pkt[ICMP].type)
else:
    print("Autre protocole ou non supporté")


# Détection couche application
if pkt.haslayer(HTTPRequest):
    print("Protocole application : HTTP Request")
elif pkt.haslayer(HTTPResponse):
    print("Protocole application : HTTP Response")
elif pkt.haslayer(DNS):
    print("Protocole application : DNS")
elif pkt.haslayer(DHCP):
    print("Protocole application : DHCP")
else:
    print("Aucun protocole application connu détecté")


print(PaquetImport[1])
print(PaquetImport[2])
