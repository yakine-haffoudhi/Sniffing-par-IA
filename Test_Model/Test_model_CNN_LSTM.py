import psycopg
import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict, Counter
from sklearn.preprocessing import LabelEncoder
import pickle

# === Mapping utilisé à l'entraînement ===

mapping = {
    "172.16.65.50": "Surveillance",
    "11.10.10.10": "Surveillance",
    "11.10.10.9": "Surveillance",
    "11.10.10.8": "Surveillance", #test
    "192.168.10.3": "Surveillance",
    "192.168.10.6": "Surveillance", #test
    "192.168.1.106": "Surveillance",
    "192.168.1.166": "Surveillance",
    "192.168.1.241": "Surveillance", #test
    "192.168.1.164": "Surveillance",
    "192.168.1.143": "Surveillance",
    "192.168.1.221": "Surveillance", #test
    "192.168.1.230": "Surveillance",
    "192.168.1.216": "Surveillance",
    "192.168.1.249": "Surveillance", #test
    "192.168.1.193": "Surveillance",
	"192.168.1.248": "Surveillance", #---
	"192.168.1.111": "Surveillance", #test
	"192.168.1.189": "Surveillance",
	"192.168.1.228": "Surveillance",

    # Surveillance receveur
    "10.10.10.12": "Surveillance",
    "10.10.10.13": "Surveillance",
    "10.10.10.14": "Surveillance", #test
    "192.168.10.12": "Surveillance",

    # Speaker
    "192.168.10.2": "Surveillance",
    "192.168.10.5": "Surveillance",
    "192.168.10.50": "Surveillance", #test
    "192.168.1.240": "Surveillance",
	"192.168.1.175": "Surveillance", #test ---
    "192.168.1.120": "Not Streaming",

    # Temps reel interactif
    "192.168.1.2": "Surveillance", #test
    "192.168.1.3": "Surveillance",
    "200.57.7.196": "Surveillance",

    # Iot non streaming
    "192.168.10.4": "Not Streaming",
    "192.168.1.159": "Not Streaming",
    "192.168.1.236": "Not Streaming",
    "192.168.1.156": "Not Streaming", #test
    "192.168.1.152": "Not Streaming", #test
    "192.168.1.196": "Not Streaming",
    "192.168.1.168": "Not Streaming", #test
    "192.168.1.112": "Not Streaming",
    "192.168.1.118": "Not Streaming", #test
    "192.168.1.223": "Not Streaming", #test
    "192.168.1.163": "Not Streaming",
    "198.18.134.11": "Not Streaming",
    "198.18.134.120": "Not Streaming", #test
    "198.18.134.150": "Not Streaming",
	"192.168.1.218": "Not Streaming", #---
	"192.168.1.172": "Not Streaming", #test
	"192.168.1.186": "Not Streaming",
    "192.168.1.205": "Not Streaming", #test

    # Media
    "192.168.137.10": "Not Streaming",
    "192.168.137.11": "Not Streaming",
    "192.168.137.12": "Not Streaming", #test
    "192.168.137.13": "Not Streaming",

	"192.168.1.179": "Not Streaming", #---

    #"193.63.53.155": "Live Broadcast",
    #"193.63.53.156": "Transfert",
}


# === Définir la classe CNNLSTMModel (copie depuis Train_CNN_LSTM) ===
class CNNLSTMModel(nn.Module):
    def __init__(self, n_num_feats, cnn_channels=64, lstm_hidden=128, n_classes=2):
        super().__init__()
        self.feat_dim = n_num_feats
        self.conv1 = nn.Conv1d(self.feat_dim, cnn_channels, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(2)
        self.lstm = nn.LSTM(cnn_channels, lstm_hidden, batch_first=True)
        self.fc = nn.Linear(lstm_hidden, n_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, num_feats):
        x = num_feats  # (B, T, feat_dim)
        x = x.permute(0, 2, 1)  # (B, F, T)
        x = self.relu(self.conv1(x))
        x = self.pool(x)
        x = x.permute(0, 2, 1)  # (B, T', C)
        _, (h_n, _) = self.lstm(x)
        out = self.dropout(h_n[-1])
        out = self.fc(out)
        return out

# === Charger les données de test depuis la base ===
conn = psycopg.connect(
    dbname="sniff",
    user="cialson",
    password="3913",
    host="localhost",
    port="5432"
)
cur = conn.cursor()
cur.execute("""
    SELECT time, ip_src, ip_dst, size, prot_transp, port_src, port_dst, direction
    FROM network_trame_camera7
""")
rows = cur.fetchall()
cur.close()
conn.close()

def is_lan(ip):
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") or ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31."):
        return 1
    return -1

direction_map = {"in": -1, "out": 1}
protocol_map = {"TCP": -1, "UDP": 1}

# === Regrouper les paquets par IP ===
ip_packets = defaultdict(list)
for pkt_time, ip_src, ip_dst, pkt_size, pkt_prot, port_src, port_dst, direction in rows:
    # Choix de la clé d'agrégation (ici ip_src, à adapter selon ton besoin)
    if direction == "out":
        ip_key = ip_src
    else:
        ip_key = ip_dst
    pkt = {
        "time": pkt_time,
        "size": float(pkt_size),
        "prot_transp": protocol_map.get(pkt_prot, 0),
        "port_src": int(port_src),
        "port_dst": int(port_dst),
        "direction": direction_map.get(direction, 0),
        "ip_src_lan": is_lan(ip_src),
        "ip_dst_lan": is_lan(ip_dst)
    }
    ip_packets[ip_key].append(pkt)

# === Construire les vocabulaires de protocoles à partir des données de test ===
with open("Models/preprocessing_params_0,84.pkl", "rb") as f:
    params = pickle.load(f)

label_encoder = params["label_encoder"]
size_mean = params["size_mean"]
size_std = params["size_std"]
dt_mean = params["dt_mean"]
dt_std = params["dt_std"]
port_src_mean = params["port_src_mean"]
port_src_std = params["port_src_std"]
port_dst_mean = params["port_dst_mean"]
port_dst_std = params["port_dst_std"]


# === Charger le modèle entraîné ===
model = CNNLSTMModel(
    n_num_feats=8,  # ou la taille réelle utilisée à l'entraînement
    cnn_channels=64,
    lstm_hidden=128,
    n_classes=len(label_encoder.classes_)
)
model.load_state_dict(torch.load("Models/cnn_lstm_model_stream_Nstream_0,84.pth", map_location="cpu"))
model.eval()


# === Prédiction pour chaque IP (fenêtrage) ===
window_size = 200  # même valeur qu'à l'entraînement
stride = 200
predictions = {}

for ip, pkts in ip_packets.items():
    if len(pkts) < window_size:
        continue
    preds = []
    for start in range(0, len(pkts) - window_size + 1, stride):
        window = pkts[start:start+window_size]
        # Préparation des features comme dans NetworkSequenceDataset
        num_feats = np.zeros((window_size, 8), dtype=np.float32)
        last_time = None
        for i, p in enumerate(window):
            num_feats[i, 0] = (p["size"] - size_mean) / size_std
            if last_time is None:
                delta = 0.0
            else:
                delta = p["time"] - last_time
            num_feats[i, 1] = (delta - dt_mean) / dt_std
            num_feats[i, 2] = (p.get("port_src", 0) - port_src_mean) / port_src_std
            num_feats[i, 3] = (p.get("port_dst", 0) - port_dst_mean) / port_dst_std
            num_feats[i, 4] = p.get("ip_src_lan", 0)
            num_feats[i, 5] = p.get("ip_dst_lan", 0)
            num_feats[i, 6] = p.get("direction", 0)
            num_feats[i, 7] = p.get("prot_transp", 0)
            last_time = p["time"]
        with torch.no_grad():
            num_feats_t = torch.tensor(num_feats, dtype=torch.float32).unsqueeze(0)
            output = model(num_feats_t)
            pred = output.argmax(1).item()
            preds.append(pred)
    if preds:
        most_common, count = Counter(preds).most_common(1)[0]
        predicted_label = label_encoder.inverse_transform([most_common])[0]
        confidence = 100 * count / len(preds)
        predictions[ip] = [predicted_label, confidence]
        print(f"IP {ip} : {predicted_label} (confiance : {confidence:.1f}%)")
        print(predictions)
        # Vérification de la correspondance avec le mapping
        if ip in mapping:
            true_label = mapping[ip]
            if predicted_label == true_label:
                print(f"  ✔ Prédiction correcte ({true_label})")
            else:
                print(f"  ✘ Prédiction incorrecte : attendu {true_label}")
        else:
            print("  (IP non présente dans le mapping)")
