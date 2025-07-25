#!/usr/bin/env python3
"""
Utilidades adicionales para PWN CTF Tool
"""

import os
import sys
import struct
import binascii

def hex_dump(data, width=16):
    """Crear hex dump de datos"""
    if isinstance(data, str):
        data = data.encode()
    
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
    
    return '\n'.join(result)

def string_to_hex(s):
    """Convertir string a hexadecimal"""
    if isinstance(s, str):
        s = s.encode()
    return s.hex()

def hex_to_string(hex_str):
    """Convertir hexadecimal a string"""
    try:
        return bytes.fromhex(hex_str).decode()
    except:
        return bytes.fromhex(hex_str)

def pack_address(addr, arch="amd64"):
    """Empaquetar dirección según arquitectura"""
    if arch == "amd64":
        return struct.pack("<Q", addr)
    elif arch == "i386":
        return struct.pack("<I", addr)
    else:
        return struct.pack("<Q", addr)

def unpack_address(data, arch="amd64"):
    """Desempaquetar dirección según arquitectura"""
    if arch == "amd64":
        return struct.unpack("<Q", data)[0]
    elif arch == "i386":
        return struct.unpack("<I", data)[0]
    else:
        return struct.unpack("<Q", data)[0]

def create_payload_template():
    """Crear template de payload"""
    template = '''#!/usr/bin/env python3
"""
Payload Template - PWN CTF Tool
"""

from pwn import *

# Configuración
binary_path = "./binary"
host = "localhost"
port = 1337

# Conectar
if len(sys.argv) > 1 and sys.argv[1] == "remote":
    p = remote(host, port)
else:
    p = process(binary_path)

# Payload
offset = 0  # Cambiar por offset real
payload = b"A" * offset
payload += p64(0xdeadbeef)  # Cambiar por dirección real

# Enviar payload
p.sendline(payload)

# Interactuar
p.interactive()
'''
    return template

def save_payload(payload, filename="payload.py"):
    """Guardar payload en archivo"""
    try:
        with open(filename, "w") as f:
            f.write(payload)
        print(f"[+] Payload guardado en {filename}")
        return True
    except Exception as e:
        print(f"[-] Error guardando payload: {e}")
        return False

def load_binary_file(filepath):
    """Cargar archivo binario"""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        print(f"[+] Archivo cargado: {len(data)} bytes")
        return data
    except Exception as e:
        print(f"[-] Error cargando archivo: {e}")
        return None

def analyze_binary_basic(filepath):
    """Análisis básico de binario"""
    try:
        data = load_binary_file(filepath)
        if not data:
            return None
        
        info = {
            "size": len(data),
            "entropy": calculate_entropy(data),
            "strings": extract_strings(data),
            "magic": data[:4].hex() if len(data) >= 4 else "N/A"
        }
        
        return info
    except Exception as e:
        print(f"[-] Error analizando binario: {e}")
        return None

def calculate_entropy(data):
    """Calcular entropía de datos"""
    if not data:
        return 0
    
    # Contar frecuencia de bytes
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calcular entropía
    entropy = 0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * (p.bit_length() - 1)
    
    return entropy

def extract_strings(data, min_length=4):
    """Extraer strings de datos binarios"""
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Caracteres imprimibles
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Agregar último string si es válido
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings[:50]  # Limitar a 50 strings

def format_bytes(data, format_type="hex"):
    """Formatear bytes en diferentes formatos"""
    if isinstance(data, str):
        data = data.encode()
    
    if format_type == "hex":
        return data.hex()
    elif format_type == "base64":
        import base64
        return base64.b64encode(data).decode()
    elif format_type == "decimal":
        return ' '.join(str(b) for b in data)
    elif format_type == "binary":
        return ' '.join(f'{b:08b}' for b in data)
    else:
        return data.hex()

def check_file_permissions(filepath):
    """Verificar permisos de archivo"""
    try:
        stat = os.stat(filepath)
        permissions = {
            "readable": os.access(filepath, os.R_OK),
            "writable": os.access(filepath, os.W_OK),
            "executable": os.access(filepath, os.X_OK),
            "size": stat.st_size,
            "mode": oct(stat.st_mode)[-3:]
        }
        return permissions
    except Exception as e:
        print(f"[-] Error verificando permisos: {e}")
        return None