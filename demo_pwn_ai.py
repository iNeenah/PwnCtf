#!/usr/bin/env python3
"""
Demo de PWN AI Analyzer
Muestra todas las capacidades de la herramienta
"""

import os
import sys
import time
import json
from pwn_ai_analyzer import PWNAIAnalyzer

def create_demo_files():
    """Crear archivos de demostración"""
    print("📁 Creando archivos de demostración...")
    
    demo_dir = "./demo_files"
    os.makedirs(demo_dir, exist_ok=True)
    
    # Archivo con flag oculta
    with open(f"{demo_dir}/secret.txt", "w") as f:
        f.write("""
Este es un archivo de texto normal.
Pero contiene un secreto: flag{demo_text_flag_found}
También hay información adicional aquí.
        """)
    
    # Código C vulnerable
    c_code = '''#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
    printf("Input: %s\\n", buffer);
}

int main() {
    char input[256];
    printf("Enter input: ");
    gets(input);  // Another vulnerability
    vulnerable_function(input);
    
    // Hidden flag: flag{demo_c_code_analysis}
    return 0;
}'''
    
    with open(f"{demo_dir}/vulnerable.c", "w") as f:
        f.write(c_code)
    
    # Script Python con vulnerabilidades
    py_code = '''#!/usr/bin/env python3
import os
import subprocess

def process_user_input(user_input):
    # Vulnerable to code injection
    eval(user_input)  # Never do this!
    
    # Another vulnerability
    os.system(f"echo {user_input}")  # Command injection
    
def main():
    user_input = input("Enter command: ")
    process_user_input(user_input)
    
    # Secret flag hidden in comment
    # flag{demo_python_code_injection}

if __name__ == "__main__":
    main()
'''
    
    with open(f"{demo_dir}/vulnerable.py", "w") as f:
        f.write(py_code)
    
    # Archivo HTML con XSS
    html_code = '''<!DOCTYPE html>
<html>
<head>
    <title>Demo Web Page</title>
</head>
<body>
    <h1>Welcome to Demo Page</h1>
    
    <script>
        // Vulnerable to XSS
        function displayUserInput() {
            var input = document.getElementById('userInput').value;
            document.getElementById('output').innerHTML = input;  // XSS vulnerability
        }
        
        // Hidden flag: flag{demo_web_xss_vulnerability}
    </script>
    
    <input type="text" id="userInput" placeholder="Enter text">
    <button onclick="displayUserInput()">Submit</button>
    <div id="output"></div>
</body>
</html>'''
    
    with open(f"{demo_dir}/vulnerable.html", "w") as f:
        f.write(html_code)
    
    # Archivo JSON con datos
    json_data = {
        "users": [
            {"name": "admin", "password": "admin123"},
            {"name": "user", "password": "password"}
        ],
        "config": {
            "debug": True,
            "secret_key": "flag{demo_json_config_leak}",
            "database_url": "mysql://root:password@localhost/app"
        }
    }
    
    with open(f"{demo_dir}/config.json", "w") as f:
        json.dump(json_data, f, indent=2)
    
    print(f"✅ Archivos de demostración creados en: {demo_dir}")
    return demo_dir

def run_demo_analysis(demo_dir, use_ai=False):
    """Ejecutar análisis de demostración"""
    print("\n🤖 INICIANDO ANÁLISIS DE DEMOSTRACIÓN")
    print("=" * 50)
    
    # Crear analizador
    api_key = None
    if use_ai:
        api_key = input("Ingresa tu API key de Gemini (opcional): ").strip()
        if not api_key:
            print("⚠️  Continuando sin IA...")
            api_key = None
    
    analyzer = PWNAIAnalyzer(gemini_api_key=api_key)
    
    # Analizar directorio de demostración
    analyzer.analyze_directory(demo_dir)
    
    return analyzer

def show_interactive_demo():
    """Mostrar demo interactivo"""
    print("🎮 PWN AI ANALYZER - DEMOSTRACIÓN INTERACTIVA")
    print("=" * 60)
    
    print("\n¿Qué te gustaría hacer?")
    print("1. 📁 Crear archivos de demostración")
    print("2. 🔍 Analizar archivos existentes")
    print("3. 🌐 Iniciar interfaz web")
    print("4. 📊 Ver ejemplo de resultados")
    print("5. 🤖 Demo completo con IA")
    print("0. ❌ Salir")
    
    while True:
        choice = input("\nSelecciona una opción: ").strip()
        
        if choice == "1":
            demo_dir = create_demo_files()
            print(f"\n✅ Archivos creados. Ahora puedes analizarlos con:")
            print(f"   python pwn_ai_analyzer.py {demo_dir}")
            
        elif choice == "2":
            target = input("Ingresa ruta del archivo o directorio: ").strip()
            if os.path.exists(target):
                analyzer = PWNAIAnalyzer()
                if os.path.isdir(target):
                    analyzer.analyze_directory(target)
                else:
                    analyzer.analyze_single_file(target)
            else:
                print("❌ Ruta no existe")
                
        elif choice == "3":
            print("🌐 Iniciando interfaz web...")
            print("Ejecuta: python web_pwn_analyzer.py")
            print("Luego ve a: http://localhost:5000")
            
        elif choice == "4":
            show_example_results()
            
        elif choice == "5":
            demo_dir = create_demo_files()
            analyzer = run_demo_analysis(demo_dir, use_ai=True)
            show_analysis_summary(analyzer)
            
        elif choice == "0":
            print("👋 ¡Hasta luego!")
            break
            
        else:
            print("❌ Opción inválida")

def show_example_results():
    """Mostrar ejemplo de resultados"""
    print("\n📊 EJEMPLO DE RESULTADOS DE ANÁLISIS")
    print("=" * 40)
    
    example_results = {
        "flags_found": [
            {
                "flag": "flag{demo_buffer_overflow}",
                "source": "./vulnerable_binary",
                "method": "string_analysis"
            },
            {
                "flag": "flag{demo_format_string}",
                "source": "./format_vuln.c",
                "method": "text_analysis"
            }
        ],
        "vulnerabilities": [
            {
                "type": "Buffer Overflow",
                "file": "./vulnerable.c",
                "function": "strcpy",
                "severity": "High"
            },
            {
                "type": "Code Injection",
                "file": "./app.py",
                "function": "eval",
                "severity": "Critical"
            }
        ],
        "analysis_summary": {
            "total_files": 15,
            "flags_found": 7,
            "vulnerabilities": 12,
            "exploits_generated": 3
        }
    }
    
    print("🚩 FLAGS ENCONTRADAS:")
    for i, flag in enumerate(example_results["flags_found"], 1):
        print(f"  {i}. {flag['flag']}")
        print(f"     📁 Fuente: {flag['source']}")
        print(f"     🔍 Método: {flag['method']}")
        print()
    
    print("⚠️  VULNERABILIDADES DETECTADAS:")
    for i, vuln in enumerate(example_results["vulnerabilities"], 1):
        print(f"  {i}. {vuln['type']} ({vuln['severity']})")
        print(f"     📁 Archivo: {vuln['file']}")
        print(f"     🔧 Función: {vuln['function']}")
        print()
    
    print("📈 RESUMEN:")
    summary = example_results["analysis_summary"]
    print(f"  📁 Archivos analizados: {summary['total_files']}")
    print(f"  🚩 Flags encontradas: {summary['flags_found']}")
    print(f"  ⚠️  Vulnerabilidades: {summary['vulnerabilities']}")
    print(f"  🔧 Exploits generados: {summary['exploits_generated']}")

def show_analysis_summary(analyzer):
    """Mostrar resumen del análisis"""
    print("\n📈 RESUMEN DEL ANÁLISIS COMPLETADO")
    print("=" * 40)
    
    print(f"📁 Archivos analizados: {len(analyzer.analysis_results)}")
    print(f"🚩 Flags encontradas: {len(analyzer.flags_found)}")
    
    if analyzer.flags_found:
        print("\n🏆 FLAGS ENCONTRADAS:")
        for i, flag_info in enumerate(analyzer.flags_found, 1):
            flag_text = flag_info.get('flag', flag_info.get('content', 'N/A'))
            print(f"  {i}. {flag_text}")
            print(f"     📁 {os.path.basename(flag_info['source'])}")
            print()
    
    print(f"\n📄 Reporte completo guardado en:")
    print(f"   {analyzer.working_directory}/analysis_report.json")
    
    print(f"\n🔧 Exploits generados en:")
    print(f"   {analyzer.working_directory}/exploits/")

def show_help():
    """Mostrar ayuda"""
    print("\n❓ AYUDA - PWN AI ANALYZER")
    print("=" * 30)
    
    print("\n🎯 MODOS DE USO:")
    print("1. 📱 Línea de comandos:")
    print("   python pwn_ai_analyzer.py <archivo_o_directorio> [api_key]")
    
    print("\n2. 🌐 Interfaz web:")
    print("   python web_pwn_analyzer.py")
    
    print("\n3. 🎮 Demo interactivo:")
    print("   python demo_pwn_ai.py")
    
    print("\n🔧 FUNCIONALIDADES:")
    print("• Análisis automático de archivos")
    print("• Detección de vulnerabilidades")
    print("• Búsqueda automática de flags")
    print("• Generación de exploits")
    print("• Chat con IA (requiere API key)")
    print("• Interfaz web drag & drop")
    
    print("\n🤖 PARA USAR IA:")
    print("1. Ve a: https://makersuite.google.com/app/apikey")
    print("2. Crea una API key de Gemini")
    print("3. Úsala en la herramienta")
    
    print("\n📞 SOPORTE:")
    print("• GitHub: [URL del repositorio]")
    print("• Issues: Para reportar bugs")
    print("• Documentación: README_PWN_AI.md")

def main():
    """Función principal del demo"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            show_help()
            return
        elif sys.argv[1] == "--create-demo":
            create_demo_files()
            return
        elif sys.argv[1] == "--example":
            show_example_results()
            return
    
    show_interactive_demo()

if __name__ == "__main__":
    main()