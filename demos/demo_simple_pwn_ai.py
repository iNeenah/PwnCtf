#!/usr/bin/env python3
"""
Simple PWN AI Analyzer Demonstration
Works without complex external dependencies
"""

import os
import sys
import time

def create_demo_challenges():
    """Create demonstration challenges"""
    print("Creating demonstration challenges...")
    
    # Crear directorio de demo
    demo_dir = "./demo_challenges"
    os.makedirs(demo_dir, exist_ok=True)
    
    # 1. Archivo con flag oculta
    with open(f"{demo_dir}/hidden_flag.txt", "w") as f:
        f.write("""
Este es un archivo de texto normal.
Pero contiene una flag oculta: flag{demo_text_flag_found}
También hay información adicional aquí.
Otra flag: CTF{text_analysis_works}
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
    
    # 5. Archivo con múltiples flags
    with open(f"{demo_dir}/multi_flags.txt", "w") as f:
        f.write("""
Archivo con múltiples flags para demostración:

Flag 1: flag{first_flag_found}
Flag 2: CTF{second_flag_detected}
Flag 3: pwn{third_flag_discovered}
Flag 4: hack{fourth_flag_located}

También contiene información sobre:
- Buffer overflow techniques
- Format string vulnerabilities
- ROP chain construction
- Heap exploitation methods
""")
    
    print(f"[+] Desafíos creados en: {demo_dir}")
    return demo_dir

def simple_flag_search(file_path):
    """Búsqueda simple de flags en archivos"""
    import re
    
    flag_patterns = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'pwn\{[^}]+\}',
        r'PWN\{[^}]+\}',
        r'hack\{[^}]+\}',
        r'HACK\{[^}]+\}',
        r'[a-zA-Z0-9_]+\{[a-zA-Z0-9_!@#$%^&*()+=\-\[\]{}|;:,.<>?/~`]+\}'
    ]
    
    flags_found = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in flags_found:
                    flags_found.append(match)
                    print(f"🚩 FLAG ENCONTRADA: {match}")
    
    except Exception as e:
        print(f"[-] Error leyendo {file_path}: {e}")
    
    return flags_found

def analyze_file_type(file_path):
    """Análisis simple del tipo de archivo"""
    extension = os.path.splitext(file_path)[1].lower()
    
    file_types = {
        '.c': 'C Source Code',
        '.cpp': 'C++ Source Code', 
        '.py': 'Python Script',
        '.js': 'JavaScript',
        '.php': 'PHP Script',
        '.html': 'HTML Document',
        '.txt': 'Text File',
        '.md': 'Markdown Document'
    }
    
    return file_types.get(extension, 'Unknown File Type')

def detect_vulnerabilities(file_path):
    """Detección simple de vulnerabilidades"""
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
        
        # Patrones de vulnerabilidades comunes
        vuln_patterns = {
            'Buffer Overflow': ['gets(', 'strcpy(', 'sprintf(', 'scanf('],
            'Format String': ['printf(', 'fprintf(', 'sprintf('],
            'Command Injection': ['system(', 'exec(', 'popen('],
            'SQL Injection': ['select * from', 'union select', "' or '1'='1"],
            'XSS': ['<script>', 'eval(', 'document.cookie'],
            'Code Injection': ['eval(', 'exec(', 'assert(']
        }
        
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    if vuln_type not in vulnerabilities:
                        vulnerabilities.append(vuln_type)
                        print(f"⚠️  Vulnerabilidad detectada: {vuln_type}")
                    break
    
    except Exception as e:
        print(f"[-] Error analizando vulnerabilidades: {e}")
    
    return vulnerabilities

def generate_simple_exploit(file_path, vulnerabilities):
    """Generar exploit simple basado en vulnerabilidades"""
    exploit_dir = "./simple_exploits"
    os.makedirs(exploit_dir, exist_ok=True)
    
    file_name = os.path.basename(file_path)
    exploit_file = f"{exploit_dir}/exploit_{file_name}.py"
    
    exploit_template = f'''#!/usr/bin/env python3
"""
Simple exploit for {file_name}
Generated by Simple PWN AI Demo
"""

import subprocess
import sys

def exploit():
    """Simple exploit based on detected vulnerabilities"""
    print("[+] Iniciando exploit simple...")
    print(f"[+] Archivo objetivo: {file_path}")
    print(f"[+] Vulnerabilidades detectadas: {vulnerabilities}")
    
    # Exploits básicos según vulnerabilidades detectadas
'''
    
    if 'Buffer Overflow' in vulnerabilities:
        exploit_template += '''
    # Buffer Overflow Exploit
    print("[+] Intentando buffer overflow...")
    
    # Payloads de diferentes tamaños
    payloads = [
        b"A" * 50,
        b"A" * 100, 
        b"A" * 200,
        b"A" * 500
    ]
    
    for i, payload in enumerate(payloads):
        print(f"[+] Probando payload {i+1}: {len(payload)} bytes")
        # Aquí iría la lógica específica del exploit
        
'''
    
    if 'Format String' in vulnerabilities:
        exploit_template += '''
    # Format String Exploit
    print("[+] Intentando format string...")
    
    format_payloads = [
        "%x " * 10,
        "%s",
        "%p " * 20,
        "%n"
    ]
    
    for payload in format_payloads:
        print(f"[+] Probando format string: {payload}")
        # Aquí iría la lógica específica del exploit
        
'''
    
    if 'Command Injection' in vulnerabilities:
        exploit_template += '''
    # Command Injection Exploit
    print("[+] Intentando command injection...")
    
    cmd_payloads = [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "; cat flag.txt"
    ]
    
    for payload in cmd_payloads:
        print(f"[+] Probando command injection: {payload}")
        # Aquí iría la lógica específica del exploit
        
'''
    
    exploit_template += '''
    print("[+] Exploit completado")

if __name__ == "__main__":
    exploit()
'''
    
    try:
        with open(exploit_file, 'w') as f:
            f.write(exploit_template)
        print(f"[+] Exploit generado: {exploit_file}")
    except Exception as e:
        print(f"[-] Error generando exploit: {e}")

def demo_simple_analysis():
    """Demostración de análisis simple"""
    print("\n" + "="*60)
    print("🔍 DEMO: ANÁLISIS SIMPLE SIN DEPENDENCIAS EXTERNAS")
    print("="*60)
    
    # Crear desafíos
    demo_dir = create_demo_challenges()
    
    # Analizar todos los archivos
    all_flags = []
    all_vulns = {}
    
    for file_name in os.listdir(demo_dir):
        file_path = os.path.join(demo_dir, file_name)
        
        if os.path.isfile(file_path):
            print(f"\n📁 Analizando: {file_name}")
            print(f"   Tipo: {analyze_file_type(file_path)}")
            
            # Buscar flags
            flags = simple_flag_search(file_path)
            all_flags.extend(flags)
            
            # Detectar vulnerabilidades
            vulns = detect_vulnerabilities(file_path)
            if vulns:
                all_vulns[file_name] = vulns
                
                # Generar exploit simple
                generate_simple_exploit(file_path, vulns)
    
    # Reporte final
    print("\n" + "="*60)
    print("📊 REPORTE FINAL")
    print("="*60)
    
    print(f"\n🚩 FLAGS ENCONTRADAS ({len(all_flags)}):")
    for i, flag in enumerate(all_flags, 1):
        print(f"  {i}. {flag}")
    
    print(f"\n⚠️  VULNERABILIDADES DETECTADAS:")
    for file_name, vulns in all_vulns.items():
        print(f"  📄 {file_name}:")
        for vuln in vulns:
            print(f"    - {vuln}")
    
    print(f"\n🔧 EXPLOITS GENERADOS:")
    exploit_dir = "./simple_exploits"
    if os.path.exists(exploit_dir):
        for exploit_file in os.listdir(exploit_dir):
            print(f"  - {exploit_file}")

def show_tool_capabilities():
    """Mostrar capacidades de las herramientas"""
    print("\n" + "="*60)
    print("🛠️  CAPACIDADES DEL SISTEMA PWN AI")
    print("="*60)
    
    capabilities = {
        "🔍 Análisis Automático": [
            "Detección automática de tipos de archivos",
            "Extracción de archivos comprimidos",
            "Búsqueda inteligente de flags",
            "Análisis de strings en binarios"
        ],
        "🤖 Inteligencia Artificial": [
            "Integración con Gemini AI",
            "Detección automática de tipos de desafíos",
            "Generación de exploits específicos",
            "Análisis contextual avanzado"
        ],
        "🔧 Generación de Exploits": [
            "Buffer Overflow con ROP chains",
            "Format String exploitation",
            "Unicode bypass techniques",
            "Race condition exploitation",
            "Arbitrary write primitives"
        ],
        "🌐 Interfaz Web": [
            "Upload de archivos para análisis",
            "Chat interactivo con IA",
            "Visualización de resultados",
            "Descarga de exploits generados"
        ],
        "🎯 Técnicas Avanzadas": [
            "Técnicas de MindCrafters writeups",
            "Browser exploitation (V8)",
            "Heap exploitation avanzada",
            "Bypass de protecciones modernas"
        ]
    }
    
    for category, features in capabilities.items():
        print(f"\n{category}:")
        for feature in features:
            print(f"  ✓ {feature}")

def show_usage_examples():
    """Mostrar ejemplos de uso"""
    print("\n" + "="*60)
    print("📚 EJEMPLOS DE USO COMPLETO")
    print("="*60)
    
    examples = [
        {
            "title": "Análisis Automático Completo",
            "command": "python pwn_ai_analyzer.py ./ctf_challenge/",
            "description": "Analiza automáticamente todos los archivos en un directorio"
        },
        {
            "title": "Análisis con IA (Gemini)",
            "command": "python pwn_ai_analyzer.py ./binary.exe AIzaSyC...",
            "description": "Análisis avanzado con inteligencia artificial"
        },
        {
            "title": "Herramientas PWN Básicas",
            "command": "python pwn_ctf_tool.py",
            "description": "Buffer overflow, ROP chains, format string"
        },
        {
            "title": "Browser Exploitation",
            "command": "python v8_exploit_tool.py",
            "description": "Exploits para V8 y navegadores"
        },
        {
            "title": "Técnicas Avanzadas",
            "command": "python advanced_pwn_solver.py",
            "description": "Unicode bypass, race conditions, arbitrary write"
        },
        {
            "title": "Interfaz Web",
            "command": "python web_pwn_analyzer.py",
            "description": "Interfaz web con chat IA y análisis interactivo"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['title']}")
        print(f"   📝 Comando: {example['command']}")
        print(f"   📖 Descripción: {example['description']}")

def main():
    """Función principal de demostración"""
    print("🤖 PWN AI ANALYZER - DEMOSTRACIÓN SIMPLIFICADA")
    print("="*60)
    print("Esta demostración muestra las funcionalidades básicas")
    print("del sistema sin requerir dependencias externas complejas")
    
    while True:
        print("\n" + "="*40)
        print("MENÚ DE DEMOSTRACIÓN")
        print("="*40)
        print("1. Análisis simple (sin dependencias)")
        print("2. Capacidades del sistema completo")
        print("3. Ejemplos de uso")
        print("4. Salir")
        
        choice = input("\nSelecciona una opción (1-4): ").strip()
        
        if choice == "1":
            demo_simple_analysis()
        elif choice == "2":
            show_tool_capabilities()
        elif choice == "3":
            show_usage_examples()
        elif choice == "4":
            print("\n👋 ¡Gracias por probar PWN AI Analyzer!")
            print("\n🚀 Para usar el sistema completo:")
            print("   1. Instala las dependencias: python install_pwn_ai.py")
            print("   2. Ejecuta: python pwn_ai_analyzer.py ./tu_desafio/")
            print("   3. Para IA: python pwn_ai_analyzer.py ./desafio/ tu_api_key")
            print("   4. Interfaz web: python web_pwn_analyzer.py")
            break
        else:
            print("[-] Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()