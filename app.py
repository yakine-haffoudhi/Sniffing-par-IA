#!/usr/bin/env python3
"""
SniffAI Dashboard PRO – Capture Live + Détection Streaming + UI Professionnelle
Ubuntu / Dual Boot ready
"""

import streamlit as st
import numpy as np
import torch
import torch.nn as nn
import pickle
import pandas as pd
from capture_reseau import NetworkMetricsExtractor
import time
import plotly.graph_objects as go
import base64
from Test_model_CNN_LSTM_CSV1 import recup_csv, is_lan
import queue
import threading

# -----------------------------
# UI & BACKGROUND
# -----------------------------
st.set_page_config(page_title="SniffAI Dashboard", layout="wide")

def set_bg(image):
    with open(image, "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data).decode()
    st.markdown(f"""
        <style>
        .stApp {{
            background-image: url("data:image/png;base64,{encoded}");
            background-size: cover;
            background-attachment: fixed;
        }}
        .glass {{
            background: rgba(0,0,0,0.55);
            padding:18px;
            border-radius:15px;
            backdrop-filter:blur(10px);
            box-shadow:0 0 15px rgba(0,0,0,0.8);
            color:white;
        }}
        .title {{
            font-size:48px;
            font-weight:900;
            color:#00eaff;
            text-align:center;
            text-shadow:0 0 18px #00eaff;
            margin-bottom:20px;
        }}
        .sub {{
            font-size:22px;
            text-align:center;
            color:#b5fffd;
            margin-bottom:30px;
        }}
        </style>
    """, unsafe_allow_html=True)

set_bg("Sniff.png")
st.markdown("<div class='title'>🚀 SniffAI – Streaming Detection Dashboard</div>", unsafe_allow_html=True)
st.markdown("<div class='sub'>Analyse réseau + IA en temps réel pour détecter les appareils en streaming</div>", unsafe_allow_html=True)

prediction_running = False
prediction_lock = threading.Lock()
devices_lock = threading.Lock()

# Prediction Thread
def run_prediction_job(df_copy, ips):
    global prediction_running
    try:
        preds = recup_csv(df_copy, ips)
        with devices_lock:            
            for ip in preds:
                devices[ip]["predi"] = preds[ip][0]
                devices[ip]["probs"] = preds[ip][1]
    finally:
        with prediction_lock:
            prediction_running = False

# -----------------------------
# SIDEBAR CONFIG
# -----------------------------
st.sidebar.title("⚙ Paramètres")
iface = st.sidebar.text_input("Interface réseau", "wlo1")
duration = st.sidebar.slider("Durée capture (s)", 5, 300, 60)
start = st.sidebar.button("🚀 Lancer la capture")

# -----------------------------
# CAPTURE & DASHBOARD
# -----------------------------
if start:
    st.info(f"📡 Capture en cours sur **{iface}** pendant {duration}s…")
    extractor = NetworkMetricsExtractor(interface=iface)
    start_time = time.time()
    devices = {}
    placeholder_table = st.empty()
    timer_placeholder = st.empty()
    df_chunk = []

    packet_queue = queue.Queue()
    stop_event = threading.Event()
    extractor = NetworkMetricsExtractor(interface=iface)
    
    # Lancer le thread de capture
    capture_thread = threading.Thread(target=extractor.capture_to_queue, args=(packet_queue, stop_event, duration))
    capture_thread.start()

    while time.time() - start_time < duration:
        elapsed = int(time.time() - start_time)
        remaining = duration - elapsed
        timer_placeholder.markdown(f"⏳ Temps restant: **{remaining}s**", unsafe_allow_html=True)

        try:
            packet = packet_queue.get(timeout=1)
            # Parse packet and append a dict to extractor.packets_data
            extractor._extract_packet_metrics(packet, target_device=None)

            # _extract_packet_metrics appends a dict to extractor.packets_data when the packet
            # contains IP/IPv6. Use that parsed dict instead of treating the raw pyshark.Packet
            # as a mapping (which raises KeyError for unknown layer names).
            if not extractor.packets_data:
                # packet was ignored by parser (non-IP or parsing failed)
                continue
            pkt = extractor.packets_data[-1]

            ip_src = pkt.get("Source_IP") or pkt.get("Source_MAC")
            ip_dst = pkt.get("Destination_IP") or pkt.get("Destination_MAC")
            
            if is_lan(ip_src) == 1 or is_lan(ip_dst) == 1:

                if is_lan(ip_src) == 1:
                    if ip_src not in devices:
                        devices[ip_src] = {"probs": 0, "count": 0, "count_mod": 0, "predi": ""}
                    devices[ip_src]["count"] += 1
                    devices[ip_src]["count_mod"] += 1

                if is_lan(ip_dst) == 1:
                    if ip_dst not in devices:
                        devices[ip_dst] = {"probs": 0, "count": 0, "count_mod": 0, "predi": ""}
                    devices[ip_dst]["count"] += 1
                    devices[ip_dst]["count_mod"] += 1

                ips = []
                bloc = False
                for ip, info in devices.items():
                    if info["count"] >= 600:
                        ips.append(ip)
                        if info["count_mod"] >= 600:
                            bloc = True
                            info["count_mod"] = 0

                if bloc and len(ips) > 0:
                    df = pd.DataFrame(extractor.packets_data).copy()
                    
                    with prediction_lock:
                        if not prediction_running:
                            prediction_running = True
                            t = threading.Thread(target=run_prediction_job, args=(df, ips), daemon=True)
                            t.start()
                        else:
                            # une prédiction est déjà en cours -> on ignore ce job
                            pass
                
                # Tableau live
                rows = []
                for mac, info in devices.items():
                    if info.get("count") >= 50:
                        rows.append({
                            "MAC / IP": mac,
                            "Classe": info.get("predi", ""),
                            "Prob Streaming (%)": round(float(info.get("probs", 0) or 0), 2),
                            "Paquets": info.get("count", 0)
                        })
                if len(rows)>0:
                    df_display = pd.DataFrame(rows).sort_values("Prob Streaming (%)", ascending=False)
                    placeholder_table.dataframe(df_display, width='stretch')
    
        except queue.Empty:
            pass

    stop_event.set()
    capture_thread.join()
    st.success(f"📦 Capture terminée: {sum([info['count'] for info in devices.values()])} paquets traités")

    # -----------------------------
    # GRAPHIQUES À LA FIN
    # -----------------------------
    if devices:
        st.markdown("### 📊 Graphiques ")
        top_devices = df_display.head(5)["MAC / IP"].tolist()
        graph_placeholders = {}
        for mac in top_devices:
            info = devices[mac]
            streaming_pct = devices[mac]["probs"]

            fig = go.Figure(go.Pie(
                values=[streaming_pct, 1-streaming_pct],
                labels=["Streaming", "Non-Streaming"],
                hole=0.6,
                marker_colors=["green", "red"],
                textinfo="percent",
                textposition="inside",
                sort=False,
                showlegend=True
            ))
            fig.update_layout(
                title_text=f"{mac}",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(t=30, b=0, l=0, r=0)
            )

            # Placeholder unique pour chaque graphique
            graph_placeholders[mac] = st.empty()
            graph_placeholders[mac].plotly_chart(fig, width='stretch')

    # -----------------------------
    # DOWNLOAD CSV
    # -----------------------------
    if not df_display.empty:
        st.download_button(
            "📥 Télécharger les résultats (CSV)",
            df_display.to_csv(index=False).encode(),
            file_name="sniffai_results.csv",
            mime="text/csv"
        )

