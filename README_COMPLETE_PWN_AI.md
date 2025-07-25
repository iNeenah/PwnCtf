# 🤖 PWN AI Analyzer - Sistema Completo de Análisis Automático para CTFs

## 📋 Descripción

PWN AI Analyzer es un sistema completo e integrado para el análisis automático de desafíos CTF (Capture The Flag). Combina técnicas tradicionales de PWN con inteligencia artificial para detectar automáticamente vulnerabilidades, generar exploits y encontrar flags.

## 🎯 Características Principales

### 🔍 Análisis Automático
- **Detección automática** de tipos de archivos (binarios, código fuente, archivos web, documentos)
- **Extracción automática** de archivos comprimidos (ZIP, TAR, GZIP)
- **Búsqueda inteligente** de flags usando patrones regex avanzados
- **Análisis de strings** y funciones vulnerables en binarios

### 🤖 Inteligencia Artificial
- **Integración con Gemini AI** para análisis contextual avanzado
- **Detección automática** del tipo de desafío CTF
- **Generación de exploits** específicos basados en el análisis
- **Sugerencias de técnicas** de explotación

### 🔧 Generación de Exploits
- **Buffer Overflow** con detección de protecciones
- **Format String** con técnicas de escritura arbitraria
- **ROP Chains** automáticos
- **Unicode Bypass** para filtros de entrada
- **Race Conditions** con multithreading
- **Arbitrary Write** para control de memoria

### 🌐 Interfaz Web
- **Upload de archivos** para análisis
- **Chat con IA** para consultas interactivas
- **Visualización de resultados** en tiempo real
- **Descarga de exploits** generados

## 🛠️ Componentes del Sistema

### 1. PWN AI Analyzer (`pwn_ai_analyzer.py`)
**Núcleo principal** del sistema con análisis automático e IA.

```python
from pwn_ai_analyzer import PWNAIAnalyzer

# Análisis básico
analyzer = PWNAIAnalyzer()
analyzer.analyze_directory("./ctf_challenge/")

# Análisis con IA
analyzer = PWNAIAnalyzer(gemini_api_key="tu_api_key")
analyzer.analyze_single_file("./binary.exe")
```

### 2. PWN CTF Tool (`pwn_ctf_tool.py`)
**Herramientas básicas** de PWN para CTFs.

```python
from pwn_ctf_tool import PWNCTFTool

tool = PWNCTFTool()
tool.buffer_overflow_exploit("./vulnerable_binary", offset=72)
tool.format_string_exploit("./format_vuln", "%8$n")
```

### 3. V8 Exploit Tool (`v8_exploit_tool.py`)
**Herramientas especializadas** para browser exploitation.

```python
from v8_exploit_tool import V8ExploitTool

v8_tool = V8ExploitTool()
v8_tool.setup_primitives()
v8_tool.arbitrary_read(target_address)
```

### 4. Advanced PWN Solver (`advanced_pwn_solver.py`)
**Técnicas avanzadas** basadas en writeups de MindCrafters.

```python
from advanced_pwn_solver import AdvancedPWNSolver

solver = AdvancedPWNSolver()
solver.unicode_bypass_technique("./challenge")
solver.multithreaded_race_condition("./race_vuln")
```

### 5. Web Interface (`web_pwn_analyzer.py`)
**Interfaz web** para análisis interactivo.

```bash
python web_pwn_analyzer.py
# Visita: http://localhost:5000
```

## 🚀 Instalación

### Instalación Automática
```bash
python install_pwn_ai.py
```

### Instalación Manual
```bash
# Instalar dependencias básicas
pip install pwntools requests

# Instalar dependencias de IA
pip install google-generativeai

# Instalar dependencias web
pip install flask flask-cors

# Herramientas del sistema (Ubuntu/Debian)
sudo apt-get install binutils gdb radare2
```

## 📖 Uso

### 1. Análisis Básico
```bash
# Analizar directorio completo
python pwn_ai_analyzer.py ./ctf_challenge/

# Analizar archivo específico
python pwn_ai_analyzer.py ./binary.exe

# Con análisis de IA
python pwn_ai_analyzer.py ./challenge.zip AIzaSyC...
```

### 2. Demostración Completa
```bash
python demo_complete_pwn_ai.py
```

### 3. Interfaz Web
```bash
python web_pwn_analyzer.py
```

## 🎯 Tipos de Desafíos Soportados

### Binarios
- **Buffer Overflow** - Detección automática de offset y generación de ROP chains
- **Format String** - Exploits de lectura/escritura arbitraria
- **Heap Exploitation** - Técnicas de tcache poisoning y fastbin attacks
- **ROP/JOP** - Construcción automática de cadenas de gadgets

### Código Fuente
- **C/C++** - Análisis de funciones vulnerables (gets, strcpy, printf)
- **Python** - Detección de eval, exec y deserialización insegura
- **JavaScript** - XSS, prototype pollution, code injection
- **PHP** - SQL injection, command injection, file inclusion

### Archivos Web
- **HTML/CSS** - Búsqueda de flags ocultas y comentarios
- **JavaScript** - Deofuscación y análisis de código
- **JSON/XML** - Parsing y búsqueda de datos sensibles

### Criptografía
- **Cifrados clásicos** - Caesar, Vigenère, substitución
- **Hashes** - MD5, SHA1, bcrypt cracking
- **RSA** - Factorización y ataques de clave débil

## 🧠 Técnicas de IA Implementadas

### Análisis Contextual
- **Detección de patrones** en código y binarios
- **Clasificación automática** de tipos de desafíos
- **Sugerencias de técnicas** de explotación específicas

### Generación de Exploits
- **Templates inteligentes** basados en el análisis
- **Personalización automática** según protecciones detectadas
- **Optimización de payloads** para diferentes arquitecturas

### Búsqueda de Flags
- **Patrones avanzados** de regex para flags
- **Análisis semántico** de contenido
- **Detección de ofuscación** y encoding

## 🔧 Técnicas Avanzadas (MindCrafters)

### Unicode Bypass
```python
# Bypass de filtros usando caracteres Unicode
unicode_payload = "\\u0041" * 100  # 'A' en Unicode
normalized = unicodedata.normalize('NFKD', payload)
```

### Race Conditions
```python
# Explotación multithreaded para condiciones de carrera
def worker_thread(thread_id):
    p = process(binary)
    time.sleep(0.001 * thread_id)  # Timing crítico
    p.sendline(payload)
```

### Arbitrary Write
```python
# Escritura arbitraria de memoria
payload = b"A" * offset
payload += p64(target_address)  # Dirección objetivo
payload += p64(value_to_write)  # Valor a escribir
```

## 📊 Reportes y Resultados

### Estructura de Reportes
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "files_analyzed": 15,
  "flags_found": [
    {
      "flag": "flag{buffer_overflow_detected}",
      "source": "vulnerable.c",
      "method": "source_code_analysis"
    }
  ],
  "analysis_results": {
    "binary.exe": {
      "challenge_type": "buffer_overflow",
      "protections": {"nx": true, "canary": false},
      "exploitation_techniques": ["rop_chain", "ret2system"]
    }
  }
}
```

### Tipos de Flags Detectadas
- **Flags directas** en texto plano
- **Flags en strings** de binarios
- **Flags en comentarios** de código
- **Flags en output** de ejecución
- **Flags ofuscadas** con encoding

## 🌐 API Web

### Endpoints Principales
```
POST /analyze - Subir archivo para análisis
GET /results - Obtener resultados del análisis
POST /chat - Chat con IA
GET /exploits - Descargar exploits generados
```

### Ejemplo de Uso
```javascript
// Upload de archivo
const formData = new FormData();
formData.append('file', file);
fetch('/analyze', {method: 'POST', body: formData});

// Chat con IA
fetch('/chat', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({message: '¿Cómo explotar este buffer overflow?'})
});
```

## 🔒 Consideraciones de Seguridad

### Ejecución Segura
- **Sandboxing** de binarios analizados
- **Timeouts** para prevenir ejecuciones infinitas
- **Validación** de inputs y archivos

### Manejo de Datos
- **No almacenamiento** de flags sensibles
- **Limpieza automática** de archivos temporales
- **Logs seguros** sin información sensible

## 🤝 Contribución

### Estructura del Proyecto
```
pwn_ai_analyzer/
├── pwn_ai_analyzer.py      # Núcleo principal
├── pwn_ctf_tool.py         # Herramientas básicas
├── v8_exploit_tool.py      # Browser exploitation
├── advanced_pwn_solver.py  # Técnicas avanzadas
├── web_pwn_analyzer.py     # Interfaz web
├── install_pwn_ai.py       # Instalador
├── demo_complete_pwn_ai.py # Demostración
└── README_COMPLETE_PWN_AI.md
```

### Agregar Nuevas Técnicas
1. Implementar en `advanced_pwn_solver.py`
2. Integrar en `pwn_ai_analyzer.py`
3. Agregar tests en `demo_complete_pwn_ai.py`
4. Documentar en README

## 📈 Roadmap

### Versión Actual (v1.0)
- ✅ Análisis automático básico
- ✅ Integración con IA (Gemini)
- ✅ Generación de exploits
- ✅ Interfaz web
- ✅ Técnicas avanzadas

### Próximas Versiones
- 🔄 Soporte para más tipos de archivos
- 🔄 Integración con más modelos de IA
- 🔄 Análisis de malware
- 🔄 Técnicas de evasión avanzadas
- 🔄 Integración con plataformas CTF

## 📞 Soporte

### Problemas Comunes
1. **pwntools no instalado**: `pip install pwntools`
2. **Gemini API no funciona**: Verificar API key
3. **Binarios no ejecutan**: Verificar permisos y arquitectura
4. **Interfaz web no carga**: Verificar puerto 5000

### Debugging
```bash
# Modo verbose
python pwn_ai_analyzer.py ./challenge --verbose

# Logs detallados
python pwn_ai_analyzer.py ./challenge --debug
```

## 📄 Licencia

Este proyecto está bajo licencia MIT. Ver `LICENSE` para más detalles.

## 🙏 Agradecimientos

- **ir0nstone** - Por el excelente material de PWN
- **MindCrafters** - Por los writeups y técnicas avanzadas
- **pwntools** - Por la librería fundamental de PWN
- **Google** - Por la API de Gemini AI

---

**¡Happy Hacking! 🚀**

Para más información y actualizaciones, visita el repositorio del proyecto.