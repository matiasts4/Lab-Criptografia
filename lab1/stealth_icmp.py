#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import time
import struct
from scapy.all import IP, ICMP, Raw, send

def cesar(texto: str, k: int) -> str:
    """
    Cifra un texto utilizando el algoritmo César.
    """
    k %= 26  # Normaliza k
    res: list[str] = []
    a = ord('a')
    for ch in texto:
        if 'a' <= ch <= 'z':
            desplazada = (ord(ch) - a + k) % 26 + a
            res.append(chr(desplazada))
        else:
            res.append(ch)
    return "".join(res)

def create_stealth_payload(char: str) -> bytes:
    """
    Crea un payload de 48 bytes que imita a un ping estándar.
    - 8 bytes: Timestamp actual.
    - 39 bytes: Patrón estándar.
    - 1 byte: El carácter del mensaje.
    """
    # 8 bytes para el timestamp (long long, 8 bytes)
    timestamp = struct.pack('d', time.time()) # 'd' is a double, 8 bytes

    # 39 bytes de patrón estándar (0x10 a 0x36)
    pattern = bytes(range(0x10, 0x37))[:39]
    
    # 1 byte para el carácter del mensaje
    data_char = char.encode('ascii')
    
    return timestamp + pattern + data_char

def send_stealth_icmp(destination: str, message: str, key: int):
    """
    Cifra un mensaje y lo envía en paquetes ICMP con payload de 48 bytes.
    """
    if os.geteuid() != 0:
        print("Error: Este script requiere privilegios de superusuario (root).", file=sys.stderr)
        sys.exit(1)

    encrypted_message = cesar(message, key)
    print(f"Iniciando envío sigiloso a: {destination}")
    print(f"Mensaje original: '{message}'")
    print(f"Mensaje cifrado (k={key}): '{encrypted_message}'")
    print("-" * 30)

    # Enviar cada caracter del mensaje cifrado
    for char in encrypted_message:
        try:
            payload = create_stealth_payload(char)
            packet = IP(dst=destination) / ICMP() / Raw(load=payload)
            send(packet, verbose=0)
            print(f"Sent 1 packet. (char: '{char}')")
            time.sleep(1)
        except Exception as e:
            print(f"Error al enviar paquete para '{char}': {e}", file=sys.stderr)
            sys.exit(1)

    # Enviar el último caracter 'b'
    try:
        final_payload = create_stealth_payload('b')
        final_packet = IP(dst=destination) / ICMP() / Raw(load=final_payload)
        send(final_packet, verbose=0)
        print("Sent 1 packet. (final char: 'b')")
    except Exception as e:
        print(f"Error al enviar paquete final: {e}", file=sys.stderr)
        sys.exit(1)

    print("-" * 30)
    print("Transmisión completada.")

def main():
    parser = argparse.ArgumentParser(
        description="Envía un mensaje cifrado vía ICMP Echo Requests con payload de 48 bytes."
    )
    parser.add_argument("--dst", required=True, help="IP/host de destino.")
    parser.add_argument("--mensaje", required=True, help="Texto a cifrar y enviar.")
    parser.add_argument("--k", required=True, type=int, help="Desplazamiento para el cifrado César.")
    
    args = parser.parse_args()
    send_stealth_icmp(args.dst, args.mensaje, args.k)

if __name__ == "__main__":
    main()
