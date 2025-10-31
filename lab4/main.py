#!/usr/bin/env python3

from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

DES_KEY_SIZE = 8
DES_IV_SIZE = 8
AES_KEY_SIZE = 32
AES_IV_SIZE = 16
DES3_KEY_SIZE = 24
DES3_IV_SIZE = 8

def imprimir_banner():
    print("Cifrado Simetrico: DES, AES-256 y 3DES en modo CBC")
    print()

def ajustar_clave(clave_usuario, tamano_requerido, nombre_algoritmo):
    clave_bytes = clave_usuario.encode('utf-8')
    longitud_original = len(clave_bytes)
    
    print(f"\n--- Ajuste de clave para {nombre_algoritmo} ---")
    print(f"Tamano requerido: {tamano_requerido} bytes")
    print(f"Tamano ingresado: {longitud_original} bytes")
    
    if longitud_original < tamano_requerido:
        bytes_faltantes = tamano_requerido - longitud_original
        bytes_aleatorios = get_random_bytes(bytes_faltantes)
        clave_ajustada = clave_bytes + bytes_aleatorios
        print(f"Clave corta. Se agregaron {bytes_faltantes} bytes aleatorios.")
        print(f"Bytes aleatorios (hex): {binascii.hexlify(bytes_aleatorios).decode()}")
    elif longitud_original > tamano_requerido:
        clave_ajustada = clave_bytes[:tamano_requerido]
        print(f"Clave larga. Se trunco a {tamano_requerido} bytes.")
    else:
        clave_ajustada = clave_bytes
        print("Clave tiene el tamano correcto.")
    
    print(f"Clave final (hex): {binascii.hexlify(clave_ajustada).decode()}")
    
    return clave_ajustada

def ajustar_iv(iv_usuario, tamano_requerido, nombre_algoritmo):
    iv_bytes = iv_usuario.encode('utf-8')
    longitud_original = len(iv_bytes)
    
    print(f"\n--- Ajuste de IV para {nombre_algoritmo} ---")
    print(f"Tamano requerido: {tamano_requerido} bytes")
    print(f"Tamano ingresado: {longitud_original} bytes")
    
    if longitud_original < tamano_requerido:
        bytes_faltantes = tamano_requerido - longitud_original
        bytes_aleatorios = get_random_bytes(bytes_faltantes)
        iv_ajustado = iv_bytes + bytes_aleatorios
        print(f"IV corto. Se agregaron {bytes_faltantes} bytes aleatorios.")
        print(f"Bytes aleatorios (hex): {binascii.hexlify(bytes_aleatorios).decode()}")
    elif longitud_original > tamano_requerido:
        iv_ajustado = iv_bytes[:tamano_requerido]
        print(f"IV largo. Se trunco a {tamano_requerido} bytes.")
    else:
        iv_ajustado = iv_bytes
        print("IV tiene el tamano correcto.")
    
    print(f"IV final (hex): {binascii.hexlify(iv_ajustado).decode()}")
    
    return iv_ajustado

def cifrar_des(clave, iv, texto_plano):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_bytes = texto_plano.encode('utf-8')
    texto_padded = pad(texto_bytes, DES.block_size)
    return cipher.encrypt(texto_padded)

def descifrar_des(clave, iv, texto_cifrado):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_bytes = unpad(texto_padded, DES.block_size)
    return texto_bytes.decode('utf-8')

def ejecutar_des(clave_usuario, iv_usuario, texto):
    print("\n" + "=" * 70)
    print(" " * 25 + "ALGORITMO DES")
    print("=" * 70)
    
    clave = ajustar_clave(clave_usuario, DES_KEY_SIZE, "DES")
    iv = ajustar_iv(iv_usuario, DES_IV_SIZE, "DES")
    
    print(f"\n--- Proceso de cifrado DES ---")
    print(f"Texto original: {texto}")
    texto_cifrado = cifrar_des(clave, iv, texto)
    texto_cifrado_hex = binascii.hexlify(texto_cifrado).decode()
    print(f"Texto cifrado (hex): {texto_cifrado_hex}")
    print(f"Longitud: {len(texto_cifrado)} bytes")
    
    print(f"\n--- Proceso de descifrado DES ---")
    texto_descifrado = descifrar_des(clave, iv, texto_cifrado)
    print(f"Texto descifrado: {texto_descifrado}")
    
    if texto == texto_descifrado:
        print("Verificacion exitosa: Coincide con el original")
    else:
        print("Error: No coincide")
    
    return texto_cifrado_hex

def cifrar_aes(clave, iv, texto_plano):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_bytes = texto_plano.encode('utf-8')
    texto_padded = pad(texto_bytes, AES.block_size)
    return cipher.encrypt(texto_padded)

def descifrar_aes(clave, iv, texto_cifrado):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_bytes = unpad(texto_padded, AES.block_size)
    return texto_bytes.decode('utf-8')

def ejecutar_aes(clave_usuario, iv_usuario, texto):
    print("\n" + "=" * 70)
    print(" " * 23 + "ALGORITMO AES-256")
    print("=" * 70)
    
    clave = ajustar_clave(clave_usuario, AES_KEY_SIZE, "AES-256")
    iv = ajustar_iv(iv_usuario, AES_IV_SIZE, "AES-256")
    
    print(f"\n--- Proceso de cifrado AES-256 ---")
    print(f"Texto original: {texto}")
    texto_cifrado = cifrar_aes(clave, iv, texto)
    texto_cifrado_hex = binascii.hexlify(texto_cifrado).decode()
    print(f"Texto cifrado (hex): {texto_cifrado_hex}")
    print(f"Longitud: {len(texto_cifrado)} bytes")
    
    print(f"\n--- Proceso de descifrado AES-256 ---")
    texto_descifrado = descifrar_aes(clave, iv, texto_cifrado)
    print(f"Texto descifrado: {texto_descifrado}")
    
    if texto == texto_descifrado:
        print("Verificacion exitosa: Coincide con el original")
    else:
        print("Error: No coincide")
    
    return texto_cifrado_hex

def cifrar_3des(clave, iv, texto_plano):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_bytes = texto_plano.encode('utf-8')
    texto_padded = pad(texto_bytes, DES3.block_size)
    return cipher.encrypt(texto_padded)

def descifrar_3des(clave, iv, texto_cifrado):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_bytes = unpad(texto_padded, DES3.block_size)
    return texto_bytes.decode('utf-8')

def ejecutar_3des(clave_usuario, iv_usuario, texto):
    print("\n" + "=" * 70)
    print(" " * 24 + "ALGORITMO 3DES")
    print("=" * 70)
    
    clave = ajustar_clave(clave_usuario, DES3_KEY_SIZE, "3DES")
    iv = ajustar_iv(iv_usuario, DES3_IV_SIZE, "3DES")
    
    print(f"\n--- Proceso de cifrado 3DES ---")
    print(f"Texto original: {texto}")
    texto_cifrado = cifrar_3des(clave, iv, texto)
    texto_cifrado_hex = binascii.hexlify(texto_cifrado).decode()
    print(f"Texto cifrado (hex): {texto_cifrado_hex}")
    print(f"Longitud: {len(texto_cifrado)} bytes")
    
    print(f"\n--- Proceso de descifrado 3DES ---")
    texto_descifrado = descifrar_3des(clave, iv, texto_cifrado)
    print(f"Texto descifrado: {texto_descifrado}")
    
    if texto == texto_descifrado:
        print("Verificacion exitosa: Coincide con el original")
    else:
        print("Error: No coincide")
    
    return texto_cifrado_hex

def main():
    imprimir_banner()
    print("Nota: Las claves e IVs se ajustaran automaticamente al tamano requerido.")
    print()
    
    print("-" * 70)
    clave_usuario = input("Ingrese la clave (key): ")
    iv_usuario = input("Ingrese el vector de inicializacion (IV): ")
    texto = input("Ingrese el texto a cifrar: ")
    print("-" * 70)
    
    texto_cifrado_des = ejecutar_des(clave_usuario, iv_usuario, texto)
    texto_cifrado_aes = ejecutar_aes(clave_usuario, iv_usuario, texto)
    texto_cifrado_3des = ejecutar_3des(clave_usuario, iv_usuario, texto)
    
    print("\n" + "=" * 70)
    print(" " * 22 + "RESUMEN DE RESULTADOS")
    print("=" * 70)
    print(f"\nTexto original: {texto}")
    print(f"\nDES (hex):     {texto_cifrado_des}")
    print(f"AES-256 (hex): {texto_cifrado_aes}")
    print(f"3DES (hex):    {texto_cifrado_3des}")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrograma interrumpido por el usuario.")
    except Exception as e:
        print(f"\n\nError: {e}")
