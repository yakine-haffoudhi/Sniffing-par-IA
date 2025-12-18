#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extraction de features (caractéristiques) du trafic réseau capturé
pour l'entraînement de modèles de machine learning.
Projet SNIFF - CNIL

CHANGEMENT (global) :
- On remplace le stockage de listes (timestamps/sizes/directions) par des stats en ligne (somme, somme des carrés, min/max).
  => Mémoire O(nb de flux actifs), plus O(nb de paquets).
- On ajoute un filtre de capture BPF (kernel) pour réduire la charge CPU/RAM.
- On gère IPv4 ET IPv6.
- On utilise une clé de flux bidirectionnelle canonique (A<->B = 1 seul flux).
- On flush les flux inactifs via idle_timeout (au lieu d’une limite max_flows).
- Direction basée sur RFC (ipaddress.is_private) au lieu de startswith('172.*').
"""

import pyshark                      # Capture live via tshark
import numpy as np                  # Stats (sqrt, inf)
import pandas as pd                 # DataFrame/CSV
from datetime import datetime       # Timestamps
from ipaddress import ip_address    # Détection IP privée IPv4/IPv6 (RFC)
import time                         # Horodatage rapide et checks périodiques
# NOTE: On retire defaultdict/json/gc puisque la nouvelle approche n'en a plus besoin
# (CHANGEMENT: plus de listes à garbage-collecter et pas de max_flows hard)

# =========================
# Utilitaires généraux
# =========================

def is_private_ip(ip: str) -> bool:
    """
    Retourne True si l'IP est privée (IPv4/IPv6) selon la RFC.
    CHANGEMENT: remplace la heuristique startswith('192.168'/'10'/'172.')
    qui était FAUSSE pour 172.* (seul 172.16/12 est privé).
    """
    try:
        return ip_address(ip).is_private
    except ValueError:
        # IP mal formée => on considère non privée pour éviter les faux positifs
        return False

def canonical_5tuple(a_ip, a_p, b_ip, b_p, proto):
    """
    Construit une clé de flux BIdirectionnelle (A<->B => UNE seule entrée).
    CHANGEMENT: évite de dupliquer les conversations en deux sens.
    """
    left  = (a_ip, int(a_p), "->", b_ip, int(b_p), proto)
    right = (b_ip, int(b_p), "->", a_ip, int(a_p), proto)
    # Tri lexicographique pour toujours choisir la même représentation
    return left if left < right else right

# =========================
# État de flux (mémoire légère)
# =========================

class FlowState:
    """
    Stocke les stats d'un flux en MODE STREAMING :
    - PAS de listes de paquets
    - Uniquement des agrégats: sommes, sommes des carrés, min/max, compteurs
    CHANGEMENT: remplace les arrays (timestamps/sizes/directions)
    """
    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "proto",
        "count", "bytes", "first_ts", "last_ts",
        "out_count", "in_count", "out_bytes", "in_bytes",
        "_sum_size", "_sum_size2", "_last_ts", "_sum_iat", "_sum_iat2",
        "min_size", "max_size", "min_iat", "max_iat"
    )

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, ts, size, outgoing):
        # Normalisation des types
        size = int(size); ts = float(ts)
        # Identité du flux (utile pour flow_id et debug)
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = int(src_port), int(dst_port)
        self.proto = proto

        # Compteurs globaux
        self.count = 1                 # 1er paquet
        self.bytes = size              # octets cumulés
        self.first_ts = ts             # timestamp départ
        self.last_ts = ts              # timestamp dernier paquet

        # Compteurs directionnels
        self.out_count = 1 if outgoing else 0
        self.in_count  = 0 if outgoing else 1
        self.out_bytes = size if outgoing else 0
        self.in_bytes  = 0 if outgoing else size

        # Stats de taille (somme, somme des carrés, min, max)
        self._sum_size  = float(size)
        self._sum_size2 = float(size) * float(size)
        self.min_size   = size
        self.max_size   = size

        # Stats IAT (Inter-Arrival Time = delta ts entre paquets consécutifs)
        self._last_ts = ts      # sert à calculer l'IAT du prochain paquet
        self._sum_iat = 0.0     # somme des IAT
        self._sum_iat2 = 0.0    # somme des IAT^2
        self.min_iat = np.inf   # initialisé à +∞ pour être remplacé au 1er IAT réel
        self.max_iat = 0.0

    def add(self, ts, size, outgoing):
        # Ajout d'un paquet au flux (mise à jour streaming)
        ts = float(ts); size = int(size)

        # Compteurs et dernier timestamp
        self.count += 1
        self.bytes += size
        self.last_ts = ts

        # Direction
        if outgoing:
            self.out_count += 1
            self.out_bytes += size
        else:
            self.in_count += 1
            self.in_bytes += size

        # Taille: mise à jour des agrégats
        self._sum_size  += size
        self._sum_size2 += float(size) * float(size)
        if size < self.min_size: self.min_size = size
        if size > self.max_size: self.max_size = size

        # IAT: delta avec le paquet précédent
        iat = ts - self._last_ts
        if iat >= 0:
            self._sum_iat  += iat
            self._sum_iat2 += iat * iat
            if iat < self.min_iat: self.min_iat = iat
            if iat > self.max_iat: self.max_iat = iat
        # Mettre à jour le "dernier ts" pour le prochain calcule d'IAT
        self._last_ts = ts

    def to_row(self):
        # Durée totale du flux (>=0)
        dur = max(0.0, self.last_ts - self.first_ts)

        # Stats de taille (moyenne, variance pop., écart-type)
        mean_sz = self._sum_size / self.count
        var_sz  = max(0.0, self._sum_size2 / self.count - mean_sz**2)  # clamp 0 pour erreurs flottantes
        std_sz  = float(np.sqrt(var_sz))

        # Stats IAT (définies si au moins 2 paquets)
        if self.count > 1:
            n_iat = self.count - 1
            mean_iat = self._sum_iat / n_iat
            var_iat  = max(0.0, self._sum_iat2 / n_iat - mean_iat**2)
            std_iat  = float(np.sqrt(var_iat))
            min_iat  = 0.0 if self.min_iat is np.inf else float(self.min_iat)
            max_iat  = float(self.max_iat)
        else:
            mean_iat = std_iat = var_iat = min_iat = max_iat = 0.0

        # Débits moyens
        pps = (self.count / dur) if dur > 0 else 0.0
        bps = (self.bytes / dur) if dur > 0 else 0.0

        # Format dict pour insertion DataFrame
        return {
            # Identifiant lisible (sens initial observé)
            "flow_id": f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}_{self.proto}",

            # Features de taille
            "packet_count": self.count,
            "total_bytes": self.bytes,
            "mean_packet_size": mean_sz,
            "std_packet_size": std_sz,
            "min_packet_size": self.min_size,
            "max_packet_size": self.max_size,
            "median_packet_size": np.nan,  # CHANGEMENT: pas de médiane exacte sans stocker; on laisse NaN (voir commentaire)

            # Features temporelles
            "flow_duration": dur,
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "min_iat": min_iat,
            "max_iat": max_iat,

            # Direction
            "outgoing_packets": self.out_count,
            "incoming_packets": self.in_count,
            "outgoing_bytes": self.out_bytes,
            "incoming_bytes": self.in_bytes,

            # Variances explicites
            "packet_size_variance": var_sz,
            "iat_variance": var_iat,

            # Débits
            "avg_packets_per_second": pps,
            "avg_bytes_per_second": bps,

            # Meta utiles
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "proto": self.proto,
            "start_ts": self.first_ts, "end_ts": self.last_ts,
        }

# =========================
# Extracteur 
# =========================

class NetworkFeatureExtractor:
    def __init__(self,
                 interface='wlan0',
                 bpf_filter=None,
                 idle_timeout=60.0,
                 min_packets=5):
        """
        interface     : interface réseau (ex: 'wlan0')
        bpf_filter    : filtre BPF (ex. "tcp or udp", "host 192.168.1.50 and tcp")
                        CHANGEMENT: filtrage kernel => grosse économie CPU/RAM.
        idle_timeout  : durée d'inactivité (s) avant flush d'un flux (borne mémoire)
        min_packets   : nombre min. de paquets pour conserver un flux
        """
        self.interface = interface
        self.bpf_filter = bpf_filter or "tcp or udp"  # par défaut: TCP ou UDP uniquement
        self.idle_timeout = float(idle_timeout)
        self.min_packets = int(min_packets)

        # CHANGEMENT: dict simple -> FlowState (plus de defaultdict de listes)
        self.flows = {}  # key(tuple) -> FlowState

        # Pour throttler le flush périodique
        self._last_flush = time.time()

    def _flush_idle(self, now_ts: float):
        """
        Flush les flux inactifs depuis idle_timeout.
        CHANGEMENT: remplace _cleanup_old_flows() (plus précis/contrôlable).
        """
        rows = []
        # list(self.flows.items()) car on modifie self.flows pendant l'itération
        for key, st in list(self.flows.items()):
            if (now_ts - st.last_ts) >= self.idle_timeout:
                if st.count >= self.min_packets:
                    rows.append(st.to_row())
                self.flows.pop(key, None)
        return rows

    def capture_and_extract(self, target_device=None, duration=120):
        """
        Capture le trafic et retourne un DataFrame de features par flux.
        target_device : IP à filtrer (deux sens)
        duration      : durée de capture (s)
        """
        print("="*70)
        print("SNIFF - Capture depuis Raspberry Pi / OpenWrt")
        print("="*70)
        print(f"[*] Interface : {self.interface}")
        print(f"[*] Filtre BPF : {self.bpf_filter}")  # CHANGEMENT: affichage du filtre BPF actif
        print(f"[*] Durée : {duration}s")
        if target_device:
            print(f"[*] Appareil cible (IP) : {target_device}")
        else:
            print("[*] Appareils : TOUS")
        print("-"*70)

        rows = []                        # contiendra les lignes finales (un dict par flux)
        start = time.time()              # début de fenêtre de capture
        packet_count = 0                 # compteur de paquets traités

        try:
            # CHANGEMENT: on active BPF au niveau de la capture
            # => libpcap/tshark rejette en kernel les paquets non pertinents
            with pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter) as capture:
                print("\n[*] Capture démarrée")
                for packet in capture.sniff_continuously():
                    now = time.time()
                    # Stop quand la durée est atteinte
                    if (now - start) >= duration:
                        break
                    try:
                        # ====== Couche IP ======
                        if hasattr(packet, 'ip'):          # IPv4
                            src_ip = packet.ip.src
                            dst_ip = packet.ip.dst
                        elif hasattr(packet, 'ipv6'):       # IPv6
                            src_ip = packet.ipv6.src
                            dst_ip = packet.ipv6.dst
                        else:
                            continue  # non-IP (ARP, etc.) => on ignore

                        # Filtre IP cible si demandé
                        if target_device and target_device not in (src_ip, dst_ip):
                            continue

                        # ====== Couche L4 (ports/proto) ======
                        if hasattr(packet, 'tcp'):
                            src_port = int(packet.tcp.srcport)
                            dst_port = int(packet.tcp.dstport)
                            proto = 'TCP'
                            size = int(packet.length)
                        elif hasattr(packet, 'udp'):
                            src_port = int(packet.udp.srcport)
                            dst_port = int(packet.udp.dstport)
                            proto = 'UDP'
                            size = int(packet.length)
                        else:
                            continue  # on ne traite que TCP/UDP

                        # Timestamp stable (datetime) -> POSIX float
                        ts = packet.sniff_time.timestamp()

                        # Direction (heuristique RFC correcte)
                        outgoing = is_private_ip(src_ip) and not is_private_ip(dst_ip)

                        # Clé de flux CANONIQUE (bidirectionnelle)
                        key = canonical_5tuple(src_ip, src_port, dst_ip, dst_port, proto)

                        # Récupérer/Créer l'état streaming
                        st = self.flows.get(key)
                        if st is None:
                            # Nouveau flux
                            self.flows[key] = FlowState(src_ip, dst_ip, src_port, dst_port, proto, ts, size, outgoing)
                        else:
                            # Flux existant -> mise à jour streaming
                            st.add(ts, size, outgoing)

                        packet_count += 1
                        # Log léger toutes les 100 unités pour moins de bruit
                        if packet_count % 100 == 0:
                            print(f"[*] Paquets traités: {packet_count}, Flux actifs: {len(self.flows)}")

                        # Flush périodique des flux inactifs (toutes ~5s)
                        if (now - self._last_flush) >= 5.0:
                            rows.extend(self._flush_idle(now))
                            self._last_flush = now

                    except Exception:
                        # Paquet mal parsé / champ manquant => on ignore sans casser la capture
                        continue

            print(f"\n[✓] Capture terminée : {packet_count} paquets")

            # Flush final de TOUS les flux restants
            for st in self.flows.values():
                if st.count >= self.min_packets:
                    rows.append(st.to_row())
            self.flows.clear()

            # DataFrame final
            df = pd.DataFrame(rows)
            print(f"[✓] {len(df)} flux analysés")
            return df

        except KeyboardInterrupt:
            # CTRL-C: on émet ce qu'on a déjà agrégé
            print("\n[!] Capture interrompue (CTRL-C). Flush des flux restants...")
            for st in self.flows.values():
                if st.count >= self.min_packets:
                    rows.append(st.to_row())
            self.flows.clear()
            df = pd.DataFrame(rows)
            print(f"[✓] {len(df)} flux analysés")
            return df
        except Exception as e:
            print(f"[!] Erreur : {e}")
            return None

    # =========================
    # I/O & visualisation
    # =========================

    def save_features(self, df, filename='network_features.csv'):
        """
        Sauvegarde CSV + résumé.
        """
        if df is not None and not df.empty:
            df.to_csv(filename, index=False)
            print(f"[✓] Features sauvegardées dans {filename}")
            print("\nRésumé des features extraites :")
            with pd.option_context("display.max_columns", None):
                print(df.describe())

    def visualize_flow_summary(self, df):
        """
        Résumé texte des flux.
        """
        if df is None or df.empty:
            print("[!] Aucune donnée à visualiser")
            return

        print("\n" + "="*60)
        print("RÉSUMÉ DES FLUX CAPTURÉS")
        print("="*60)

        print(f"\nNombre total de flux: {len(df)}")
        print(f"Nombre total de paquets: {df['packet_count'].sum():.0f}")
        print(f"Volume total de données: {df['total_bytes'].sum()/1024:.2f} KB")

        print("\nTop 5 flux par volume de données:")
        top_flows = df.nlargest(5, 'total_bytes')[['flow_id', 'packet_count', 'total_bytes', 'flow_duration']]
        for _, row in top_flows.iterrows():
            print(f"  {row['flow_id'][:70]}...")
            print(f"    Paquets: {row['packet_count']:.0f}, Bytes: {row['total_bytes']:.0f}, Durée: {row['flow_duration']:.2f}s")

# =========================


def main():
    print("="*60)
    print("SNIFF - Extraction de Features pour Machine Learning")
    print("="*60 + "\n")

    interface = input("Interface réseau (défaut: wlan0): ").strip() or "wlan0"
    target = input("Appareil cible IP (vide = tous): ").strip() or None

    try:
        duration = input("Durée de capture en secondes (défaut: 120): ").strip()
        duration = int(duration) if duration else 120
    except ValueError:
        duration = 120

    # CHANGEMENT: au lieu de 'max_flows', on expose des options performantes
    # (BPF + idle_timeout + min_packets). On garde la même UX interactive.
    bpf = input("Filtre BPF (vide = 'tcp or udp'): ").strip() or "tcp or udp"
    try:
        idle = input("Timeout d'inactivité d'un flux en s (défaut: 60): ").strip()
        idle = float(idle) if idle else 60.0
    except ValueError:
        idle = 60.0
    try:
        minpk = input("Seuil min. de paquets par flux (défaut: 5): ").strip()
        minpk = int(minpk) if minpk else 5
    except ValueError:
        minpk = 5

    # CHANGEMENT: max_flows est passé à None/ignoré; conservé pour compat si besoin
    extractor = NetworkFeatureExtractor(
        interface=interface,
        bpf_filter=bpf,
        idle_timeout=idle,
        min_packets=minpk
    )

    df = extractor.capture_and_extract(target_device=target, duration=duration)

    if df is not None and not df.empty:
        extractor.visualize_flow_summary(df)

        save = input("\nSauvegarder les features? (o/n): ").strip().lower()
        if save == 'o':
            filename = input("Nom du fichier (défaut: network_features.csv): ").strip() or "network_features.csv"
            extractor.save_features(df, filename)
    else:
        print("[!] Aucune feature générée.")

if __name__ == "__main__":
    main()
