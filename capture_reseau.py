#!/usr/bin/env python3
"""
Module de capture et extraction de métriques réseau (IPv4/IPv6)
Optimisé pour Raspberry Pi / WSL
"""

import pyshark
import pandas as pd
from datetime import datetime
import gc
import queue

class NetworkMetricsExtractor:
    def __init__(self, interface='wlo1', max_packets=100000):
        self.interface = interface
        self.max_packets = max_packets
        self.packets_data = []

    def capture_to_queue(self, packet_queue, stop_event, duration, target_device=None):
        """Capture le trafic et extrait les métriques (chunk par défaut 2s)"""
        capture = pyshark.LiveCapture(interface=self.interface)
        start_time = datetime.now()
        try:
            for packet in capture.sniff_continuously():
                if (datetime.now() - start_time).seconds >= duration:
                    break
                if len(self.packets_data) >= self.max_packets:
                    break
                packet_queue.put(packet)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"[!] Erreur: {e}")


    def _extract_packet_metrics(self, packet, target_device):
        try:
            if not (hasattr(packet, 'ip') or hasattr(packet, 'ipv6')):
                return

            if hasattr(packet, 'ip'):
                src_ip, dst_ip, ip_ver = packet.ip.src, packet.ip.dst, "IPv4"
            else:
                src_ip, dst_ip, ip_ver = packet.ipv6.src, packet.ipv6.dst, "IPv6"

            if target_device and target_device not in [src_ip, dst_ip]:
                return

            ts = float(packet.sniff_timestamp)
            size = int(packet.length)
            proto, sport, dport = "OTHER", 0, 0
            src_mac, dst_mac = packet.eth.src, packet.eth.dst

            if hasattr(packet, 'tcp'):
                proto, sport, dport = "TCP", int(packet.tcp.srcport), int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                proto, sport, dport = "UDP", int(packet.udp.srcport), int(packet.udp.dstport)

            self.packets_data.append({
                "TimeStamp": ts,
                "Packet_Size": size,
                "Transport_Protocol": proto,
                "Source_Port": sport,
                "Destination_Port": dport,
                "Source_IP": src_ip,
                "Destination_IP": dst_ip,
                "IP_Version": ip_ver,
                "Source_MAC": src_mac,
                "Destination_MAC": dst_mac
            })
        except:
            pass

    def save_metrics(self, df, filename='network_metrics.csv'):
        if df is not None and not df.empty:
            df.to_csv(filename, index=False)
            print(f"[✓] Métriques sauvegardées dans {filename}")
