#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import re
from collections import defaultdict
from scapy.all import rdpcap, ICMP, IP, Raw

# --- Colores para salida ---
GREEN = '\033[92m'
RESET = '\033[0m'
YELLOW = '\033[93m'

# Lista simple de palabras comunes en español
PALABRAS_COMUNES_ES = {
    'a','ante','con','de','desde','en','entre','hacia','hasta','para','por','sin','sobre','tras',
    'el','la','los','las','un','una','unos','unas','y','o','u','que','se','es','lo','al','del'
}

def cesar(texto: str, k: int) -> str:
    """Cifra/descifra César. Para descifrar usa k negativo."""
    k %= 26
    a = ord('a')
    out = []
    for ch in texto:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - a + k) % 26 + a))
        else:
            out.append(ch)
    return "".join(out)

def calculate_score(texto: str) -> int:
    """
    Puntaje simple de plausibilidad del español.
    """
    score = 0
    tokens = re.findall(r"[a-záéíóúñü]+", texto.lower())
    for t in tokens:
        if t in PALABRAS_COMUNES_ES:
            score += 1
    for bg in (" de ", " la ", " el ", " en ", " y "):
        if bg in " " + texto.lower() + " ":
            score += 1
    return score

def process_pcap(pcap_file: str, destination: str):
    print(f"[*] Analizando '{pcap_file}' para Echo Requests de 48 bytes hacia '{destination}'...")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error leyendo PCAP: {e}", file=sys.stderr)
        sys.exit(1)

    candidatos = []
    for idx, pkt in enumerate(packets):
        if not (pkt.haslayer(IP) and pkt[IP].dst == destination and 
                pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and 
                pkt.haslayer(Raw) and len(pkt[Raw].load) == 48):
            continue
        
        try:
            # Extraer el último byte del payload, que contiene el caracter oculto
            ch = pkt[Raw].load[-1:].decode("ascii")
            candidatos.append({
                "idx": idx,
                "time": float(pkt.time),
                "src": pkt[IP].src,
                "id": pkt[ICMP].id,
                "seq": pkt[ICMP].seq,
                "char": ch,
            })
        except (IndexError, UnicodeDecodeError):
            continue

    if not candidatos:
        print("[!] No se encontraron Echo Requests válidos (payload de 48 bytes).")
        return

    print(f"[*] Echo Requests válidos encontrados: {len(candidatos)}")

    grupos = defaultdict(list)
    for item in candidatos:
        grupos[(item["src"], item["id"])].append(item)

    flujo_key, flujo_pkts = max(grupos.items(), key=lambda kv: len(kv[1]))
    print(f"[*] Flujo seleccionado: src={flujo_key[0]}, id={flujo_key[1]} (paquetes: {len(flujo_pkts)})")

    unique_seqs = {p["seq"] for p in flujo_pkts}
    if len(unique_seqs) > 1:
        flujo_pkts.sort(key=lambda p: p["seq"])
    else:
        flujo_pkts.sort(key=lambda p: p["time"])

    reconstruido = "".join(p["char"] for p in flujo_pkts)
    print(f"\n[+] Mensaje cifrado reconstruido ({len(reconstruido)} caracteres):")
    print(f"{YELLOW}{reconstruido}{RESET}")

    ends_b = reconstruido.endswith('b')
    encrypted_message = reconstruido
    if ends_b:
        print("[+] Verificación: último carácter fue 'b'. Se retirará para descifrado.")
        encrypted_message = reconstruido[:-1]
    else:
        print("[!] El último carácter no es 'b'. Se descifrará la cadena completa.")

    print("\n[*] Iniciando fuerza bruta contra César...")
    print("-" * 50)
    
    mejor_k = -1
    mejor_score = -1
    intentos = []

    for k in range(26):
        candidato = cesar(encrypted_message, -k)
        score = calculate_score(candidato)
        intentos.append((k, candidato, score))
        if score > mejor_score:
            mejor_score = score
            mejor_k = k
        elif score == mejor_score:
            if mejor_k != 0 and k == 0:
                mejor_k = 0
            elif k < mejor_k and mejor_k != 0:
                 mejor_k = k


    for k, texto, score in intentos:
        if k == mejor_k:
            print(f"{GREEN}[k={k:2d}] {texto}  (score={score})  << Más probable{RESET}")
        else:
            print(f"[k={k:2d}] {texto}  (score={score})")

    print("-" * 50)

def main():
    ap = argparse.ArgumentParser(description="Reconstruye mensaje ICMP y realiza fuerza bruta César.")
    ap.add_argument("--pcap", required=True, help="Ruta al archivo .pcap")
    ap.add_argument("--dst", required=True, help="IP de destino de los Echo Request")
    args = ap.parse_args()
    process_pcap(args.pcap, args.dst)

if __name__ == "__main__":
    main()
