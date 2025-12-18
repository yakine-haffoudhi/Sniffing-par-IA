import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict, Counter
import pickle
import pandas as pd

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

def is_lan(ip):
    if ip.startswith("fe80:") or ip.startswith("fc00:") or ip.startswith("fd00:") or ip.startswith("::1") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") or ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31."):
        return 1
    return -1

def recup_csv(df, ips):
    
    direction_map = {"in": -1, "out": 1}
    protocol_map = {"TCP": -1, "UDP": 1}

    # === Regrouper les paquets par IP ===
    ip_packets = defaultdict(list)
    for ip in ips:
        for _, row in df.iterrows():
            ip_src = row["Source_IP"]
            ip_dst = row["Destination_IP"]

            if ip_src == ip or ip_dst == ip:
                pkt_time = float(row["TimeStamp"])
                pkt_size = float(row["Packet_Size"])
                pkt_prot = row["Transport_Protocol"]
                port_src = int(row["Source_Port"])
                port_dst = int(row["Destination_Port"])

                if ip_src == ip:
                    direction = "out"
                else:
                    direction = "in"

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
                ip_packets[ip].append(pkt)

    return prediction_model(ip_packets)


def prediction_model(ip_packets):
    # Charger modèle/params en cache (load_model() les garde en mémoire)
    model, label_encoder, params = load_model()

    size_mean = params["size_mean"]
    size_std = params["size_std"]
    dt_mean = params["dt_mean"]
    dt_std = params["dt_std"]
    port_src_mean = params["port_src_mean"]
    port_src_std = params["port_src_std"]
    port_dst_mean = params["port_dst_mean"]
    port_dst_std = params["port_dst_std"]

    # === Prédiction pour chaque IP (fenêtrage) ===
    window_size = 200  # même valeur qu'à l'entraînement
    stride = 200
    predictions = {}

    for ip, pkts in ip_packets.items():
        #if len(pkts) < window_size:
        #    continue
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
                probs = torch.softmax(output, dim=1).cpu().numpy()[0]
                preds.append(probs)
        if preds:
            # Moyenne des probabilités par classe sur toutes les fenêtres
            avg_probs = np.mean(preds, axis=0)
            idx_stream = list(label_encoder.classes_).index("Surveillance") if "Surveillance" in list(label_encoder.classes_) else 0
            streaming_prob = avg_probs[idx_stream]*100
            predicted_label = label_encoder.inverse_transform([int(np.argmax(avg_probs))])[0]
            predictions[ip] = [predicted_label, streaming_prob]
            #print(f"IP {ip} : {predicted_label} (probabilité streaming : {streaming_prob:.1f}%)")

    return predictions


# Caching loader -------------------------------------------------------------
_MODEL_CACHE = None
_ENC_CACHE = None
_PARAMS_CACHE = None

def load_model():
    """Charge et met en cache le modèle, l'encodeur de labels et les params.
    Retourne (model, label_encoder, params)."""
    global _MODEL_CACHE, _ENC_CACHE, _PARAMS_CACHE
    if _MODEL_CACHE is None:
        with open("preprocessing_params_final_0,72.pkl", "rb") as f:
            _PARAMS_CACHE = pickle.load(f)
        _ENC_CACHE = _PARAMS_CACHE["label_encoder"]
        _MODEL_CACHE = CNNLSTMModel(
            n_num_feats=8,
            cnn_channels=64,
            lstm_hidden=128,
            n_classes=len(_ENC_CACHE.classes_)
        )
        _MODEL_CACHE.load_state_dict(torch.load("cnn_lstm_model_stream_Nstream_final_0,72.pth", map_location="cpu"))
        _MODEL_CACHE.eval()
    return _MODEL_CACHE, _ENC_CACHE, _PARAMS_CACHE