import psycopg
import numpy as np
import joblib
from collections import defaultdict, Counter

# Charger le modèle Random Forest
rf, class_names = joblib.load("rf_model_large.joblib")

# Connexion à la base
conn = psycopg.connect(
    dbname="sniff",
    user="cialson",
    password="3913",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

# Récupération des données de la nouvelle table
cur.execute("SELECT time, mac, size, prot_transp, prot_appl FROM network_trame_small_test")
rows = cur.fetchall()
cur.close()
conn.close()

# Regrouper par MAC (ou autre identifiant si besoin)
from collections import defaultdict
mac_packets = defaultdict(list)
for row in rows:
    pkt_time, pkt_mac, pkt_size, pkt_prot, pkt_sprot = row
    mac_packets[pkt_mac.lower()].append({
        "time": pkt_time,
        "size": pkt_size,
        "prot_transp": pkt_prot,
        "prot_appl": pkt_sprot
    })

# Même fonction d'extraction de features que pour l'entraînement
app_protocols = ["HTTP", "DNS", "DHCP", "MDNS", "SSDP", "MQTT", "None"]

def extract_rf_features_from_packets(packets):
    if len(packets) == 0:
        return None
    sizes, deltas = [], []
    last_time = None
    n_tcp = n_udp = n_icmp = n_other = 0
    app_counts = {proto: 0 for proto in app_protocols}
    for pkt in packets:
        sizes.append(pkt["size"])
        if last_time is None:
            delta = 0.0
        else:
            delta = pkt["time"] - last_time
        deltas.append(delta)
        last_time = pkt["time"]
        if pkt["prot_transp"] == "TCP":
            n_tcp += 1
        elif pkt["prot_transp"] == "UDP":
            n_udp += 1
        elif pkt["prot_transp"] == "ICMP":
            n_icmp += 1
        else:
            n_other += 1
        proto_appl = str(pkt["prot_appl"]).upper()
        if proto_appl in app_counts:
            app_counts[proto_appl] += 1
    sizes = np.array(sizes)
    deltas = np.array(deltas)
    duration = packets[-1]["time"] - packets[0]["time"] if len(packets) > 1 else 0.0
    freq = len(packets) / duration if duration > 0 else 0.0
    app_ratios = [app_counts[proto] / len(packets) for proto in app_protocols]
    feats = [
        sizes.mean(), sizes.std(), sizes.min(), sizes.max(),
        deltas.mean(), deltas.std(),
        n_tcp/len(packets), n_udp/len(packets),
        n_icmp/len(packets), n_other/len(packets),
        freq
    ] + app_ratios
    return np.array(feats, dtype=np.float32)

# Prédiction sur chaque fenêtre
window_size = 10
for mac, pkts in mac_packets.items():
    if len(pkts) < window_size:
        continue
    preds = []
    for start in range(0, len(pkts) - window_size + 1, window_size):
        window = pkts[start:start+window_size]
        feats = extract_rf_features_from_packets(window)
        if feats is not None:
            feats = feats.reshape(1, -1)
            pred = rf.predict(feats)[0]
            preds.append(pred)
    if preds:
        most_common = Counter(preds).most_common(1)[0][0]
        print(f"MAC {mac} : {class_names[most_common]}")
