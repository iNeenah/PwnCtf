# 🤖 PWN AI Analyzer

**Herramienta unificada con IA para análisis automático de desafíos CTF**

Analiza automáticamente archivos, identifica tipos de desafíos PWN y los resuelve usando inteligencia artificial.

## 🚀 Características Principales

### 🔍 Análisis Automático
- **Detección inteligente** de tipos de archivo (binarios, código fuente, archivos web, etc.)
- **Extracción automática** de archivos comprimidos (ZIP, TAR, 7Z)
- **Búsqueda automática** de flags en múltiples formatos
- **Análisis de vulnerabilidades** en binarios y código fuente

### 🤖 Integración con IA
- **Google Gemini AI** para análisis avanzado
- **Chat interactivo** sobre los resultados del análisis
- **Generación automática** de exploits
- **Recomendaciones específicas** de técnicas PWN

### 🌐 Interfaz Web
- **Subida de archivos** drag & drop
- **Análisis en tiempo real** con barra de progreso
- **Chat con IA** integrado
- **Descarga de resultados** completos

### 📊 Análisis Completo
- **Binarios ejecutables**: Protecciones, arquitectura, strings, funciones
- **Código fuente**: Vulnerabilidades, funciones sospechosas, flags
- **Archivos web**: XSS, SQL injection, manipulación de cookies
- **Documentos**: Extracción de texto y búsqueda de flags

## 📦 Instalación

### Instalación Automática
```bash
python install_pwn_ai.py
```

### Instalación Manual
```bash
pip install pwntools flask google-generativeai python-magic requests werkzeug jinja2
```

## 🎯 Uso

### 1. Línea de Comandos
```bash
# Análisis básico
python pwn_ai_analyzer.py ./challenge_directory/

# Con IA (requiere API key de Gemini)
python pwn_ai_analyzer.py ./binary.exe AIzaSyC...

# Analizar archivo ZIP
python pwn_ai_analyzer.py ./ctf_challenge.zip
```

### 2. Interfaz Web
```bash
# Iniciar servidor web
python web_pwn_analyzer.py

# Acceder en el navegador
http://localhost:5000
```

## 🔑 Configuración de Gemini AI

1. Ve a [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Crea una nueva API key
3. Úsala en la herramienta:
   - **CLI**: Como segundo parámetro
   - **Web**: En el campo "Gemini API Key"

## 📁 Estructura de Resultados

```
analysis_workspace/
├── extracted/              # Archivos extraídos
├── exploits/              # Exploits generados
├── flags/                 # Flags encontradas
└── analysis_report.json   # Reporte completo
```

## 🎮 Ejemplos de Uso

### Ejemplo 1: Análisis de Binario
```bash
python pwn_ai_analyzer.py ./vulnerable_binary
```

**Salida esperada:**
```
🔍 ANALIZANDO DIRECTORIO: ./
⚙️  Binario ejecutable detectado: vulnerable_binary
[+] Arquitectura: amd64
[+] Protecciones: NX=True, Canary=False, PIE=False
🚩 FLAG ENCONTRADA: flag{buffer_overflow_detected}
🔧 Generando exploit automático...
[+] Exploit generado: ./analysis_workspace/exploits/exploit_vulnerable_binary.py
```

### Ejemplo 2: Análisis de ZIP con IA
```bash
python pwn_ai_analyzer.py ./ctf_challenge.zip AIzaSyC_your_api_key_here
```

**Funcionalidades adicionales con IA:**
- Análisis contextual de vulnerabilidades
- Recomendaciones específicas de explotación
- Generación de exploits más sofisticados
- Explicaciones detalladas de técnicas PWN

### Ejemplo 3: Interfaz Web
1. Ejecuta: `python web_pwn_analyzer.py`
2. Ve a: `http://localhost:5000`
3. Arrastra tu archivo ZIP al área de subida
4. Ingresa tu API key de Gemini (opcional)
5. Haz clic en "Iniciar Análisis"
6. Chatea con la IA sobre los resultados

## 🔧 Tipos de Análisis Soportados

### Binarios Ejecutables
- **ELF** (Linux)
- **PE** (Windows)
- **Mach-O** (macOS)

**Análisis incluye:**
- Protecciones de seguridad (NX, ASLR, PIE, Canary)
- Arquitectura y punto de entrada
- Strings y funciones importadas
- Pruebas de ejecución automáticas
- Detección de vulnerabilidades comunes

### Código Fuente
- **C/C++**: Buffer overflows, format strings
- **Python**: Code injection, deserialization
- **JavaScript**: XSS, prototype pollution
- **PHP**: SQL injection, RCE

### Archivos Web
- **HTML/CSS**: XSS, CSRF
- **JavaScript**: DOM manipulation, prototype pollution
- **JSON**: Injection attacks

### Archivos Comprimidos
- **ZIP, 7Z, TAR, GZIP**
- Extracción automática y análisis recursivo
- Preservación de estructura de directorios

## 🤖 Capacidades de IA

### Análisis Contextual
```
🤖 Análisis IA: Este binario presenta una vulnerabilidad de buffer overflow 
clásica en la función main(). La ausencia de stack canaries y la 
arquitectura x64 sugieren usar una técnica de ROP chain para bypass de NX.

Recomendaciones:
1. Usar patrón cíclico para encontrar offset
2. Buscar gadgets con ROPgadget
3. Construir cadena ROP para llamar system("/bin/sh")
```

### Chat Interactivo
- **Pregunta**: "¿Cómo exploto este buffer overflow?"
- **IA**: "Basándome en el análisis, este binario tiene un buffer overflow en la función vulnerable(). Te recomiendo usar un payload de 72 bytes para controlar RIP, seguido de una cadena ROP..."

## 📊 Dashboard Web

Accede a `http://localhost:5000/dashboard` para ver:
- Historial de todos los análisis
- Estadísticas de flags encontradas
- Descarga de resultados anteriores
- Estado de análisis en progreso

## 🛠️ Troubleshooting

### Error: "No module named 'magic'"
```bash
# En Ubuntu/Debian
sudo apt-get install libmagic1

# En macOS
brew install libmagic

# Luego reinstalar
pip install python-magic
```

### Error: "Gemini API key invalid"
- Verifica que tu API key sea correcta
- Asegúrate de tener créditos en tu cuenta de Google AI
- Revisa que la API esté habilitada

### Error: "Permission denied" en binarios
```bash
chmod +x ./binary_file
```

## 🎯 Casos de Uso Típicos

### 1. CTF en Vivo
```bash
# Análisis rápido de todos los archivos del CTF
python pwn_ai_analyzer.py ./ctf_files/ YOUR_API_KEY

# Revisar flags encontradas automáticamente
cat ./analysis_workspace/analysis_report.json | grep -i flag
```

### 2. Análisis Forense
```bash
# Analizar archivo sospechoso
python pwn_ai_analyzer.py ./suspicious_file.exe

# Revisar strings y comportamiento
cat ./analysis_workspace/analysis_report.json
```

### 3. Educación/Aprendizaje
- Usa la interfaz web para análisis interactivo
- Chatea con la IA para entender vulnerabilidades
- Descarga exploits generados para estudiar

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -am 'Agregar nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abre un Pull Request

## 📄 Licencia

MIT License - Ver archivo LICENSE para detalles

## 🙏 Agradecimientos

- **ir0nstone** - Fuente principal de conocimiento PWN
- **Google Gemini** - Capacidades de IA
- **pwntools** - Framework de explotación
- **Comunidad CTF** - Por compartir conocimiento

---

**¿Necesitas ayuda?** Abre un issue en GitHub o contacta al equipo de desarrollo.

**¿Encontraste un bug?** ¡Repórtalo! Toda contribución es bienvenida.

**¿Quieres una nueva funcionalidad?** Sugiere mejoras en las issues.