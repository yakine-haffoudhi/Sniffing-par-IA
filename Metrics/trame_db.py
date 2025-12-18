import psycopg
from datetime import datetime
from scapy.all import sniff, wrpcap, rdpcap, get_if_list
import time

mapping = {
    "172.16.65.50": "Surveillance emetteur",
    "192.168.1.2": "Temps reel interactif",
    "192.168.1.3": "Temps reel interactif",
    "200.57.7.196": "Temps reel interactif",
    "193.63.53.155": "Live Broadcast",
    "193.63.53.156": "Transfert",

    "11.10.10.10": "Surveillance emetteur",
    "11.10.10.9": "Surveillance emetteur",
    "11.10.10.8": "Surveillance emetteur",
    "10.10.10.12": "Surveillance receveur",
    "10.10.10.13": "Surveillance receveur",
    "10.10.10.14": "Surveillance receveur",
    
    "192.168.10.3": "Surveillance emetteur",
    "192.168.10.6": "Surveillance emetteur",
    "192.168.10.12": "Surveillance receveur",
    "192.168.10.2": "Speaker",
    "192.168.10.5": "Speaker",
    "192.168.10.50": "Speaker",
    "192.168.10.4": "Iot non streaming",
'''
    "192.168.1.106": "Surveillance emetteur",
    "192.168.1.159": "Iot non streaming",
    "192.168.1.240": "Speaker",
    "192.168.1.166": "Surveillance emetteur",
    "192.168.1.241": "Surveillance emetteur",
    "192.168.1.236": "Iot non streaming",
    "192.168.1.156": "Iot non streaming",
    "192.168.1.165": "Surveillance emetteur",
    "192.168.1.152": "Iot non streaming",
    "192.168.1.143": "Surveillance emetteur",
    "192.168.1.221": "Surveillance emetteur",
    "192.168.1.230": "Surveillance emetteur",
    "192.168.1.120": "Speaker (simple)",
    "192.168.1.196": "Iot non streaming",
    "192.168.1.168": "Iot non streaming",
    "192.168.1.112": "Iot non streaming",
    "192.168.1.118": "Iot non streaming",
    "192.168.1.223": "Iot non streaming",
    "192.168.1.163": "Iot non streaming",
    "192.168.1.216": "Surveillance emetteur",
    "192.168.1.249": "Surveillance emetteur",
    "192.168.1.193": "Surveillance mouvement",
'''
    "192.168.137.10": "Iot non streaming",
    "192.168.137.11": "Iot non streaming",
    "192.168.137.12": "Iot non streaming",
    "192.168.137.13": "Iot non streaming",

    "198.18.134.11": "industry non streaming",
    "198.18.134.120": "industry non streaming",
    "198.18.134.150": "Personal",


	"192.168.1.249":	"Surveillance emetteur",
	"192.168.1.111":	"Surveillance emetteur",
	"192.168.1.218":	"Iot non streaming",
	"192.168.1.172":	"Iot non streaming",
	"192.168.1.186":	"Iot non streaming",
	"192.168.1.179":	"Personal",
	"192.168.1.175":	"Speaker",
	"192.168.1.189":	"Surveillance emetteur",
    "192.168.1.205":	"Iot non streaming",
	"192.168.1.228":	"Surveillance emetteur",

}

# Protocoles de transport pertinents (couche 4 OSI)
transport_protocols = [
    "TCP",      # Transmission Control Protocol
    "UDP"      # User Datagram Protocol
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
#network_trame_camera19
#iot_non_stream15
#network_trame_speaker6
cur.execute("""
    CREATE TABLE IF NOT EXISTS network_trame_camera19 ( 
    id SERIAL PRIMARY KEY,
    time FLOAT NOT NULL,
    ip_src TEXT NOT NULL,
    ip_dst TEXT NOT NULL,
    size INT NOT NULL,
    prot_transp TEXT NOT NULL,
    port_src INT NOT NULL,
    port_dst INT NOT NULL,
    direction TEXT NOT NULL
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


print("lecture du fichier")

PaquetImport = rdpcap("../Data/2023-08-12-short.pcap")

print("enregistrement des données")

def normalize_mac(mac):
    if isinstance(mac, bytes) and len(mac) >= 6:
        return ":".join(f"{b:02x}" for b in mac[:6])
    elif isinstance(mac, str) and len(mac.split(":")) == 6:
        return mac.lower()
    else:
        return str(mac) 

for pkt in PaquetImport:

    # IP source/destination
    if pkt.haslayer("IP"):
        ip_src = pkt["IP"].src
        ip_dst = pkt["IP"].dst
    else:
        ip_src = "None"
        ip_dst = "None"
        
    '''
    if pkt.haslayer("Ether"):
        pkt_mac = normalize_mac(pkt["Ether"].src)
    elif pkt.haslayer("CookedLinux"):
        pkt_mac = normalize_mac(getattr(pkt["CookedLinux"], "src", None))
        if pkt_mac in mapping and ip_src != "None":
            print(f"{pkt_mac} : {ip_src}")
    '''

    if ip_src in mapping or ip_dst in mapping:

        pkt_time = pkt.time
        pkt_size = len(pkt)
        pkt_prot = "None"
        bloc = True

        # Ports source/destination
        if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
            port_src = pkt.sport
            port_dst = pkt.dport
        else:
            port_src = -1
            port_dst = -1

        # Détermination de la direction
        if ip_src in mapping:
            direction = "out"
            #ip_src = "192.168.1.248"
        else:
            direction = "in"
            #ip_dst = "192.168.1.248"


        for layer in pkt.layers():
            prot = layer.__name__

            if prot == "DNS":
                bloc = False
            if prot in transport_protocols:
                pkt_prot = prot
 
        if bloc and pkt_prot != "None":
            #Insérer des données
            cur.execute(
            "INSERT INTO network_trame_camera19 (time, ip_src, ip_dst, size, prot_transp, port_src, port_dst, direction) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (pkt_time, ip_src, ip_dst, pkt_size, pkt_prot, port_src, port_dst, direction)
            )
            conn.commit()


#read_data()


# Fermeture du curseur et de la connexion
cur.close()
conn.close()
