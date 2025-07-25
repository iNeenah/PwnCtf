#!/usr/bin/env python3
"""
Demostración completa del PWN AI Analyzer
Muestra todas las funcionalidades integradas
"""

import os
import sys
import time
from pwn_ai_analyzer import PWNAIAnalyzer

def create_demo_challenges():
    """Crear desafíos de demostración"""
    print("🎯 Creando desafíos de demostración...")
    
    # Crear directorio de demo
    demo_dir = "./demo_challenges"
    os.makedirs(demo_dir, exist_ok=True)
    
    # 1. Archivo con flag oculta
    with open(f"{demo_dir}/hidden_flag.txt", "w") as f:
        f.write("""
Este es un archivo de texto normal.
Pero contiene una flag oculta: flag{demo_text_flag_found}
También hay información adicional aquí.
""")
    
    # 2. Código fuente vulnerable
    with open(f"{demo_dir}/vulnerable.c", "w") as f:
        f.write("""
#include <stdio.h>
#include <string.h>

// Flag oculta: flag{source_code_analysis_works}

int main() {
    char buffer[64];
    printf("Enter password: ");
    gets(buffer);  // Vulnerable function!
    
    if (strcmp(buffer, "secret123") == 0) {
        printf("Access granted! Flag: flag{buffer_overflow_detected}\\n");
        system("/bin/sh");
    } else {
        printf("Access denied\\n");
    }
    
    return 0;
}
""")
    
    # 3. Script web con vulnerabilidades
    with open(f"{demo_dir}/web_vuln.php", "w") as f:
        f.write("""
<?php
// Web vulnerability demo
// Hidden flag: flag{web_analysis_successful}

$user = $_GET['user'];
$pass = $_GET['pass'];

// SQL Injection vulnerability
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";

if ($user == "admin' OR '1'='1") {
    echo "Flag: flag{sql_injection_found}";
}

// XSS vulnerability
echo "<script>alert('$user')</script>";

// Command injection
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);  // Very dangerous!
}
?>
""")
    
    # 4. Archivo JavaScript con ofuscación
    with open(f"{demo_dir}/obfuscated.js", "w") as f:
        f.write("""
// Obfuscated JavaScript challenge
var _0x1234 = ['flag{javascript_deobfuscation}', 'admin', 'password'];

function checkPassword(input) {
    if (input === _0x1234[1]) {
        console.log('Access granted: ' + _0x1234[0]);
        return true;
    }
    return false;
}

// Another hidden flag: flag{js_source_analysis}
eval(atob('Y29uc29sZS5sb2coImZsYWd7ZXZhbF9kZXRlY3RlZH0iKTs='));
""")
    
    # 5. Archivo binario simulado (hexdump)
    with open(f"{demo_dir}/fake_binary.hex", "w") as f:
        f.write("""
7f454c46020101000000000000000000
flag{hex_analysis_works}
4141414141414141414141414141414141
system("/bin/sh")
gets(buffer)
printf("Enter input: ")
""")
    
    print(f"[+] Desafíos creados en: {demo_dir}")
    return demo_dir

def demo_basic_analysis():
    """Demostración de análisis básico"""
    print("\n" + "="*60)
    print("🔍 DEMO: ANÁLISIS BÁSICO SIN IA")
    print("="*60)
    
    # Crear desafíos
    demo_dir = create_demo_challenges()
    
    # Crear analizador sin IA
    analyzer = PWNAIAnalyzer()
    
    # Analizar directorio completo
    analyzer.analyze_directory(demo_dir)
    
    return analyzer

def demo_ai_analysis():
    """Demostración con análisis de IA"""
    print("\n" + "="*60)
    print("🤖 DEMO: ANÁLISIS CON IA (GEMINI)")
    print("="*60)
    
    # Solicitar API key (opcional para demo)
    api_key = input("Ingresa tu Gemini API key (o Enter para saltar): ").strip()
    
    if not api_key:
        print("[-] Saltando análisis con IA")
        return None
    
    # Crear desafíos
    demo_dir = create_demo_challenges()
    
    # Crear analizador con IA
    analyzer = PWNAIAnalyzer(gemini_api_key=api_key)
    
    # Analizar directorio con IA
    analyzer.analyze_directory(demo_dir)
    
    return analyzer

def demo_exploit_generation():
    """Demostración de generación de exploits"""
    print("\n" + "="*60)
    print("🔧 DEMO: GENERACIÓN DE EXPLOITS")
    print("="*60)
    
    # Crear binario de prueba simulado
    test_binary = "./demo_challenges/test_binary"
    
    # Simular análisis de binario
    fake_analysis = {
        "challenge_type": "buffer_overflow",
        "architecture": "amd64",
        "protections": {
            "nx": True,
            "canary": False,
            "pie": False,
            "relro": "Partial"
        },
        "vulnerable_functions": [
            {"function": "gets", "description": "Buffer overflow vulnerability"}
        ],
        "exploitation_techniques": ["rop_chain", "ret2system"],
        "suggested_offset": 72
    }
    
    # Crear analizador
    analyzer = PWNAIAnalyzer()
    
    # Generar diferentes tipos de exploits
    exploit_types = [
        ("buffer_overflow", fake_analysis),
        ("format_string", {**fake_analysis, "challenge_type": "format_string"}),
        ("unicode_bypass", {**fake_analysis, "challenge_type": "unicode_bypass"}),
        ("race_condition", {**fake_analysis, "challenge_type": "race_condition"}),
        ("arbitrary_write", {**fake_analysis, "challenge_type": "arbitrary_write"})
    ]
    
    for exploit_type, analysis in exploit_types:
        print(f"\n[+] Generando exploit para: {exploit_type}")
        analysis["challenge_type"] = exploit_type
        analyzer.generate_advanced_exploit(f"demo_{exploit_type}", analysis)
    
    print(f"\n[+] Exploits generados en: {analyzer.working_directory}/exploits/")

def demo_integration_test():
    """Demostración de integración completa"""
    print("\n" + "="*60)
    print("🚀 DEMO: INTEGRACIÓN COMPLETA")
    print("="*60)
    
    # Importar otras herramientas
    try:
        from pwn_ctf_tool import PWNCTFTool
        from v8_exploit_tool import V8ExploitTool
        from advanced_pwn_solver import AdvancedPWNSolver
        
        print("[+] Todas las herramientas PWN disponibles")
        
        # Crear instancias
        basic_tool = PWNCTFTool()
        v8_tool = V8ExploitTool()
        advanced_solver = AdvancedPWNSolver()
        ai_analyzer = PWNAIAnalyzer()
        
        print("[+] Herramientas inicializadas:")
        print("    - PWN CTF Tool (básico)")
        print("    - V8 Exploit Tool (browser)")
        print("    - Advanced PWN Solver (técnicas avanzadas)")
        print("    - AI Analyzer (análisis automático)")
        
        # Mostrar capacidades integradas
        print("\n[+] Capacidades integradas:")
        print("    🎯 Análisis automático de archivos")
        print("    🤖 IA para detección de vulnerabilidades")
        print("    🔧 Generación automática de exploits")
        print("    🌐 Interfaz web para análisis interactivo")
        print("    📊 Reportes detallados con flags encontradas")
        print("    🚀 Técnicas avanzadas de MindCrafters")
        
        return True
        
    except ImportError as e:
        print(f"[-] Error importando herramientas: {e}")
        return False

def demo_web_interface():
    """Demostración de interfaz web"""
    print("\n" + "="*60)
    print("🌐 DEMO: INTERFAZ WEB")
    print("="*60)
    
    try:
        from web_pwn_analyzer import app
        print("[+] Interfaz web disponible")
        print("[+] Para iniciar la interfaz web:")
        print("    python web_pwn_analyzer.py")
        print("[+] Luego visita: http://localhost:5000")
        print("\n[+] Funcionalidades web:")
        print("    - Upload de archivos para análisis")
        print("    - Chat con IA para consultas")
        print("    - Visualización de resultados")
        print("    - Descarga de exploits generados")
        
    except ImportError:
        print("[-] Interfaz web no disponible")

def show_usage_examples():
    """Mostrar ejemplos de uso"""
    print("\n" + "="*60)
    print("📚 EJEMPLOS DE USO")
    print("="*60)
    
    examples = [
        {
            "title": "Análisis básico de directorio",
            "command": "python pwn_ai_analyzer.py ./ctf_challenge/",
            "description": "Analiza todos los archivos en un directorio"
        },
        {
            "title": "Análisis con IA",
            "command": "python pwn_ai_analyzer.py ./binary.exe AIzaSyC...",
            "description": "Análisis avanzado con Gemini AI"
        },
        {
            "title": "Análisis de archivo específico",
            "command": "python pwn_ai_analyzer.py ./vulnerable.c",
            "description": "Analiza un archivo individual"
        },
        {
            "title": "Interfaz web",
            "command": "python web_pwn_analyzer.py",
            "description": "Inicia interfaz web interactiva"
        },
        {
            "title": "Herramienta básica PWN",
            "command": "python pwn_ctf_tool.py",
            "description": "Herramientas básicas de PWN"
        },
        {
            "title": "Exploits V8/Browser",
            "command": "python v8_exploit_tool.py",
            "description": "Herramientas para browser exploitation"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['title']}")
        print(f"   Comando: {example['command']}")
        print(f"   Descripción: {example['description']}")

def main():
    """Función principal de demostración"""
    print("🤖 PWN AI ANALYZER - DEMOSTRACIÓN COMPLETA")
    print("="*60)
    print("Esta demostración muestra todas las funcionalidades integradas")
    print("del sistema PWN AI para análisis automático de CTFs")
    
    while True:
        print("\n" + "="*40)
        print("MENÚ DE DEMOSTRACIÓN")
        print("="*40)
        print("1. Análisis básico (sin IA)")
        print("2. Análisis con IA (Gemini)")
        print("3. Generación de exploits")
        print("4. Test de integración")
        print("5. Interfaz web")
        print("6. Ejemplos de uso")
        print("7. Salir")
        
        choice = input("\nSelecciona una opción (1-7): ").strip()
        
        if choice == "1":
            demo_basic_analysis()
        elif choice == "2":
            demo_ai_analysis()
        elif choice == "3":
            demo_exploit_generation()
        elif choice == "4":
            demo_integration_test()
        elif choice == "5":
            demo_web_interface()
        elif choice == "6":
            show_usage_examples()
        elif choice == "7":
            print("\n👋 ¡Gracias por probar PWN AI Analyzer!")
            break
        else:
            print("[-] Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()