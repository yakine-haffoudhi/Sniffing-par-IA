import psycopg
from datetime import datetime
from scapy.all import sniff, wrpcap, rdpcap, get_if_list, IP, TCP, UDP, ICMP, IPv6, DNS, DHCP
from scapy.layers.http import HTTPRequest, HTTPResponse
import time

mapping = {
    "40:f6:bc:bc:89:7b": "Echo Dot (4th Gen)",
    "68:3a:48:0d:d4:1c": "Aeotec Smart Hub",
    "70:ee:50:57:95:29": "Netatmo Smart Indoor Security Camera",
    "54:af:97:bb:8d:8f": "TP-Link Tapo Pan/Tilt Wi-Fi Camera",
    "70:09:71:9d:ad:10": "32' Smart Monitor M80B UHD",
    "00:16:6c:d7:d5:f9": "SAMSUNG Pan/Tilt 1080P Wi-Fi Camera",
    "40:ac:bf:29:04:d4": "EZVIZ Security Camera",
    "10:5a:17:b8:a2:0b": "TOPERSUN Smart Plug",
    "10:5a:17:b8:9f:70": "TOPERSUN Smart Plug",
    "fc:67:1f:53:fa:6e": "Perfk Motion Sensor",
    "1c:90:ff:bf:89:46": "Perfk Motion Sensor",
    "cc:a7:c1:6a:b5:78": "NEST Protect smoke alarm",
    "70:ee:50:96:bb:dc": "Netatmo Weather Station",
    "00:24:e4:e3:15:6e": "Withings Body+ (Scales)",
    "00:24:e4:e4:55:26": "Withings Body+ (Scales)",
    "00:24:e4:f6:91:38": "Withings Connect (Blood Pressure)",
    "00:24:e4:f7:ee:ac": "Withings Connect (Blood Pressure)",
    "70:3a:2d:4a:48:e2": "TUYA Smartdoor Bell",
    "b0:02:47:6f:63:37": "Pix-Star Easy Digital Photo Frame",
    "84:69:93:27:ad:35": "HP Envy",
    "18:48:be:31:4b:49": "Echo Show 8",
    "74:d4:23:32:a2:d7": "Echo Show 8",
    "6e:fe:2f:5a:d7:7e": "GALAXY Watch5 Pro",
    "90:48:6c:08:da:8a": "Ring Video Doorbell",
    "64:bc:0c:67:cc:5f": "Réseaux sociaux",
    "00:24:9b:6d:b8:89": "Ordinateur malveillant",
    "b8:27:eb:d1:b7:ef": "Ordinateur malveillant",
    "00:07:7c:88:6e:83": "Router",
    "00:07:7c:88:6e:63": "Router",
    "00:07:7c:29:de:41": "Router",
    "00:07:7c:29:de:61": "Router",
    "00:07:7c:8c:43:83": "Router",
    "00:07:7c:8c:43:63": "Router",
    "b8:27:eb:6d:4f:4b": "PLC",
    "b8:27:eb:5b:50:19": "PLC",
    "b8:27:eb:15:88:9c": "Ordinateur"
}

# Protocoles de transport pertinents (couche 4 OSI)
transport_protocols = [
    "TCP",      # Transmission Control Protocol
    "UDP",      # User Datagram Protocol
    "ICMP",     # Internet Control Message Protocol
    "SCTP",     # Stream Control Transmission Protocol
    "DCCP",     # Datagram Congestion Control Protocol
    "UDPLite",  # Lightweight UDP
]

# Protocoles applicatifs pertinents (couche 7 OSI)
application_protocols = [
    "HTTP",     # HyperText Transfer Protocol
    "DNS",      # Domain Name System
    "DHCP",     # Dynamic Host Configuration Protocol
    "MQTT",     # Message Queuing Telemetry Transport (IoT)
    "SSDP",     # Simple Service Discovery Protocol (IoT)
    "MDNS",     # Multicast DNS (IoT)
    "CoAP",     # Constrained Application Protocol (IoT)
    "FTP",      # File Transfer Protocol
    "SMTP",     # Simple Mail Transfer Protocol
    "POP3",     # Post Office Protocol v3
    "IMAP",     # Internet Message Access Protocol
    "SNMP",     # Simple Network Management Protocol
    "Telnet",   # Telnet
    "SSH",      # Secure Shell
    "NTP",      # Network Time Protocol
    "LDAP",     # Lightweight Directory Access Protocol
    "SMB",      # Server Message Block
    "RDP",      # Remote Desktop Protocol
    "TFTP",     # Trivial File Transfer Protocol
    "RTSP",     # Real Time Streaming Protocol
    "SIP",      # Session Initiation Protocol
    "XMPP",     # Extensible Messaging and Presence Protocol
    "AMQP",     # Advanced Message Queuing Protocol
    "STUN",     # Session Traversal Utilities for NAT
    "WebSocket" # WebSocket Protocol
]


# Connexion à la base de données
conn = psycopg.connect(
dbname="sniff",
user="cialson",
password="3913",
host="localhost",
port="5432"
)

# Création d'un curseur pour exécuter des commandes SQL
cur = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS network_trame_11 (
    id SERIAL PRIMARY KEY,
    time FLOAT NOT NULL,
    mac TEXT NOT NULL,
    size INT NOT NULL,
    prot_transp TEXT NOT NULL,
    prot_appl TEXT NOT NULL
);
""")

# Validation des changements
conn.commit()

def read_data():
    
    #Lire des données
    cur.execute("SELECT * FROM network_trame")
    rows = cur.fetchall()
    for row in rows:
        print(row)


def normalize_mac(mac):
    if isinstance(mac, bytes) and len(mac) >= 6:
        return ":".join(f"{b:02x}" for b in mac[:6])
    elif isinstance(mac, str) and len(mac.split(":")) == 6:
        return mac.lower()
    else:
        return str(mac)
    
print("lecture du fichier")

PaquetImport = rdpcap("../Data/2023-08-26.pcap")

print("enregistrement des données")


for pkt in PaquetImport:

    # Affichage MAC source/dest si possible
    if pkt.haslayer("Ether"):
        pkt_mac = normalize_mac(pkt["Ether"].src)
    elif pkt.haslayer("CookedLinux"):
        pkt_mac = normalize_mac(getattr(pkt["CookedLinux"], "src", None))
    else:
        pkt_mac = "None"

    if pkt_mac in mapping:


        pkt_time = pkt.time
        pkt_size = len(pkt)
        pkt_prot = "None"
        pkt_sprot = "None"

        for layer in pkt.layers():
            prot = layer.__name__

            if prot in transport_protocols:
                pkt_prot = prot

            if prot in application_protocols:
                pkt_sprot = prot


        #Insérer des données
        cur.execute("INSERT INTO network_trame_11 (time, mac, size, prot_transp, prot_appl) VALUES (%s, %s, %s, %s, %s)", (pkt_time, pkt_mac, pkt_size, pkt_prot, pkt_sprot))
        conn.commit()


#read_data()


# Fermeture du curseur et de la connexion
cur.close()
conn.close()
