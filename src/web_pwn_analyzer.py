#!/usr/bin/env python3
"""
Web PWN Analyzer - Web interface for automatic CTF analysis
Allows uploading ZIP files and analyzing them with AI
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import os
import json
import zipfile
import tempfile
import shutil
from werkzeug.utils import secure_filename
from pwn_ai_analyzer import PWNAIAnalyzer
import google.generativeai as genai
from datetime import datetime
import threading
import uuid

app = Flask(__name__, template_folder='../templates')
app.secret_key = 'pwn_analyzer_secret_key_2024'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Configuración
UPLOAD_FOLDER = './uploads'
RESULTS_FOLDER = './results'
ALLOWED_EXTENSIONS = {'zip', '7z', 'tar', 'gz', 'exe', 'elf', 'bin', 'py', 'js', 'c', 'cpp', 'txt', 'md'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# Almacén de análisis en progreso
analysis_status = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    gemini_key = request.form.get('gemini_key', '')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Generar ID único para este análisis
        analysis_id = str(uuid.uuid4())
        
        # Guardar archivo
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, f"{analysis_id}_{filename}")
        file.save(file_path)
        
        # Iniciar análisis en hilo separado
        analysis_status[analysis_id] = {
            'status': 'starting',
            'progress': 0,
            'filename': filename,
            'timestamp': datetime.now().isoformat()
        }
        
        thread = threading.Thread(
            target=run_analysis,
            args=(analysis_id, file_path, gemini_key)
        )
        thread.start()
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'message': 'Análisis iniciado'
        })
    
    return jsonify({'error': 'Tipo de archivo no permitido'}), 400

def run_analysis(analysis_id, file_path, gemini_key):
    """Ejecutar análisis en hilo separado"""
    try:
        analysis_status[analysis_id]['status'] = 'analyzing'
        analysis_status[analysis_id]['progress'] = 10
        
        # Crear analizador
        analyzer = PWNAIAnalyzer(gemini_api_key=gemini_key if gemini_key else None)
        
        # Configurar directorio de trabajo específico
        analyzer.working_directory = f"./results/{analysis_id}"
        analyzer.setup_workspace()
        
        analysis_status[analysis_id]['progress'] = 30
        
        # Analizar archivo
        if os.path.isfile(file_path):
            analyzer.analyze_single_file(file_path)
        
        analysis_status[analysis_id]['progress'] = 80
        
        # Generar reporte
        analyzer.generate_final_report()
        
        # Guardar resultados
        results = {
            'flags_found': analyzer.flags_found,
            'analysis_results': analyzer.analysis_results,
            'total_files': len(analyzer.analysis_results),
            'total_flags': len(analyzer.flags_found)
        }
        
        results_file = f"./results/{analysis_id}/web_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        analysis_status[analysis_id]['status'] = 'completed'
        analysis_status[analysis_id]['progress'] = 100
        analysis_status[analysis_id]['results'] = results
        
    except Exception as e:
        analysis_status[analysis_id]['status'] = 'error'
        analysis_status[analysis_id]['error'] = str(e)

@app.route('/status/<analysis_id>')
def get_status(analysis_id):
    """Obtener estado del análisis"""
    if analysis_id not in analysis_status:
        return jsonify({'error': 'Analysis not found'}), 404
    
    return jsonify(analysis_status[analysis_id])

@app.route('/results/<analysis_id>')
def get_results(analysis_id):
    """Obtener resultados del análisis"""
    if analysis_id not in analysis_status:
        return jsonify({'error': 'Analysis not found'}), 404
    
    status = analysis_status[analysis_id]
    if status['status'] != 'completed':
        return jsonify({'error': 'Analysis not completed'}), 400
    
    return jsonify(status.get('results', {}))

@app.route('/download/<analysis_id>')
def download_results(analysis_id):
    """Descargar resultados completos"""
    if analysis_id not in analysis_status:
        return jsonify({'error': 'Analysis not found'}), 404
    
    results_dir = f"./results/{analysis_id}"
    if not os.path.exists(results_dir):
        return jsonify({'error': 'Results not found'}), 404
    
    # Crear ZIP con todos los resultados
    zip_path = f"{results_dir}/complete_results.zip"
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for root, dirs, files in os.walk(results_dir):
            for file in files:
                if file != 'complete_results.zip':
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, results_dir)
                    zipf.write(file_path, arcname)
    
    return send_file(zip_path, as_attachment=True, 
                    download_name=f"pwn_analysis_{analysis_id}.zip")

@app.route('/ai_chat', methods=['POST'])
def ai_chat():
    """Chat con IA sobre análisis"""
    data = request.get_json()
    analysis_id = data.get('analysis_id')
    message = data.get('message')
    gemini_key = data.get('gemini_key')
    
    if not all([analysis_id, message, gemini_key]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if analysis_id not in analysis_status:
        return jsonify({'error': 'Analysis not found'}), 404
    
    try:
        # Configurar Gemini
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-pro')
        
        # Obtener contexto del análisis
        status = analysis_status[analysis_id]
        results = status.get('results', {})
        
        # Crear prompt con contexto
        context_prompt = f"""
        Contexto del análisis CTF:
        - Archivos analizados: {results.get('total_files', 0)}
        - Flags encontradas: {results.get('total_flags', 0)}
        - Flags: {results.get('flags_found', [])}
        
        Pregunta del usuario: {message}
        
        Responde como un experto en CTF y PWN, siendo específico y técnico.
        Si el usuario pregunta sobre exploits, proporciona código específico.
        """
        
        response = model.generate_content(context_prompt)
        
        return jsonify({
            'response': response.text,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': f'AI Error: {str(e)}'}), 500

@app.route('/dashboard')
def dashboard():
    """Dashboard con todos los análisis"""
    return render_template('dashboard.html', analyses=analysis_status)

# Crear templates HTML
def create_templates():
    """Crear templates HTML"""
    templates_dir = './templates'
    os.makedirs(templates_dir, exist_ok=True)
    
    # Template principal
    index_html = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PWN AI Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .upload-area {
            border: 2px dashed #007bff;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            background: #f8f9fa;
            transition: all 0.3s ease;
        }
        .upload-area:hover {
            border-color: #0056b3;
            background: #e3f2fd;
        }
        .flag-item {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 10px;
            margin: 5px 0;
        }
        .progress-container {
            display: none;
        }
        .chat-container {
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <span class="navbar-brand">
                <i class="fas fa-robot"></i> PWN AI Analyzer
            </span>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-upload"></i> Subir Archivo para Análisis</h5>
                    </div>
                    <div class="card-body">
                        <form id="uploadForm" enctype="multipart/form-data">
                            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                                <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                                <h5>Arrastra archivos aquí o haz clic para seleccionar</h5>
                                <p class="text-muted">Soporta: ZIP, 7Z, TAR, EXE, ELF, Python, C/C++, JavaScript, etc.</p>
                                <input type="file" id="fileInput" name="file" style="display: none;" accept=".zip,.7z,.tar,.gz,.exe,.elf,.bin,.py,.js,.c,.cpp,.txt,.md">
                            </div>
                            
                            <div class="mt-3">
                                <label for="geminiKey" class="form-label">Gemini API Key (opcional)</label>
                                <input type="password" class="form-control" id="geminiKey" name="gemini_key" placeholder="AIzaSyC...">
                                <small class="form-text text-muted">Para análisis avanzado con IA</small>
                            </div>
                            
                            <button type="submit" class="btn btn-primary mt-3">
                                <i class="fas fa-search"></i> Iniciar Análisis
                            </button>
                        </form>
                        
                        <div class="progress-container mt-3">
                            <div class="progress">
                                <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                            </div>
                            <div class="mt-2">
                                <span id="statusText">Iniciando análisis...</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4" id="resultsCard" style="display: none;">
                    <div class="card-header">
                        <h5><i class="fas fa-flag"></i> Resultados del Análisis</h5>
                    </div>
                    <div class="card-body" id="resultsContent">
                        <!-- Resultados se cargarán aquí -->
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-comments"></i> Chat con IA</h5>
                    </div>
                    <div class="card-body">
                        <div class="chat-container" id="chatContainer">
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle"></i>
                                Sube un archivo y obtén tu API key de Gemini para chatear sobre el análisis.
                            </div>
                        </div>
                        <div class="input-group mt-3">
                            <input type="text" class="form-control" id="chatInput" placeholder="Pregunta sobre el análisis..." disabled>
                            <button class="btn btn-primary" id="sendChat" disabled>
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-3">
                    <div class="card-header">
                        <h5><i class="fas fa-info-circle"></i> Información</h5>
                    </div>
                    <div class="card-body">
                        <h6>Tipos de análisis:</h6>
                        <ul class="list-unstyled">
                            <li><i class="fas fa-cog text-primary"></i> Binarios ejecutables</li>
                            <li><i class="fas fa-code text-success"></i> Código fuente</li>
                            <li><i class="fas fa-globe text-info"></i> Archivos web</li>
                            <li><i class="fas fa-archive text-warning"></i> Archivos comprimidos</li>
                        </ul>
                        
                        <h6 class="mt-3">Funcionalidades:</h6>
                        <ul class="list-unstyled">
                            <li><i class="fas fa-search text-primary"></i> Búsqueda automática de flags</li>
                            <li><i class="fas fa-shield-alt text-danger"></i> Detección de vulnerabilidades</li>
                            <li><i class="fas fa-robot text-success"></i> Análisis con IA</li>
                            <li><i class="fas fa-download text-info"></i> Generación de exploits</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentAnalysisId = null;
        
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            const fileInput = document.getElementById('fileInput');
            const geminiKey = document.getElementById('geminiKey').value;
            
            if (!fileInput.files[0]) {
                alert('Por favor selecciona un archivo');
                return;
            }
            
            formData.append('file', fileInput.files[0]);
            formData.append('gemini_key', geminiKey);
            
            // Mostrar progreso
            document.querySelector('.progress-container').style.display = 'block';
            document.getElementById('resultsCard').style.display = 'none';
            
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentAnalysisId = data.analysis_id;
                    checkStatus(data.analysis_id);
                    
                    // Habilitar chat si hay API key
                    if (geminiKey) {
                        document.getElementById('chatInput').disabled = false;
                        document.getElementById('sendChat').disabled = false;
                    }
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error subiendo archivo');
            });
        });
        
        function checkStatus(analysisId) {
            fetch(`/status/${analysisId}`)
            .then(response => response.json())
            .then(data => {
                const progressBar = document.querySelector('.progress-bar');
                const statusText = document.getElementById('statusText');
                
                progressBar.style.width = data.progress + '%';
                statusText.textContent = `Estado: ${data.status} (${data.progress}%)`;
                
                if (data.status === 'completed') {
                    loadResults(analysisId);
                } else if (data.status === 'error') {
                    statusText.textContent = 'Error: ' + data.error;
                } else {
                    setTimeout(() => checkStatus(analysisId), 2000);
                }
            });
        }
        
        function loadResults(analysisId) {
            fetch(`/results/${analysisId}`)
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('resultsCard').style.display = 'block';
            });
        }
        
        function displayResults(data) {
            const resultsContent = document.getElementById('resultsContent');
            
            let html = `
                <div class="row">
                    <div class="col-md-6">
                        <h6><i class="fas fa-chart-bar"></i> Estadísticas</h6>
                        <p>Archivos analizados: <strong>${data.total_files}</strong></p>
                        <p>Flags encontradas: <strong>${data.total_flags}</strong></p>
                    </div>
                    <div class="col-md-6">
                        <a href="/download/${currentAnalysisId}" class="btn btn-success">
                            <i class="fas fa-download"></i> Descargar Resultados
                        </a>
                    </div>
                </div>
            `;
            
            if (data.flags_found && data.flags_found.length > 0) {
                html += '<h6 class="mt-3"><i class="fas fa-flag"></i> Flags Encontradas</h6>';
                data.flags_found.forEach((flag, index) => {
                    html += `
                        <div class="flag-item">
                            <strong>Flag ${index + 1}:</strong> 
                            <code>${flag.flag || flag.content}</code><br>
                            <small class="text-muted">
                                Fuente: ${flag.source} | Método: ${flag.method}
                            </small>
                        </div>
                    `;
                });
            }
            
            resultsContent.innerHTML = html;
        }
        
        // Chat functionality
        document.getElementById('sendChat').addEventListener('click', sendChatMessage);
        document.getElementById('chatInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
        
        function sendChatMessage() {
            const chatInput = document.getElementById('chatInput');
            const message = chatInput.value.trim();
            const geminiKey = document.getElementById('geminiKey').value;
            
            if (!message || !currentAnalysisId || !geminiKey) return;
            
            // Agregar mensaje del usuario
            addChatMessage('user', message);
            chatInput.value = '';
            
            // Enviar a la IA
            fetch('/ai_chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    analysis_id: currentAnalysisId,
                    message: message,
                    gemini_key: geminiKey
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.response) {
                    addChatMessage('ai', data.response);
                } else {
                    addChatMessage('ai', 'Error: ' + data.error);
                }
            })
            .catch(error => {
                addChatMessage('ai', 'Error de conexión');
            });
        }
        
        function addChatMessage(sender, message) {
            const chatContainer = document.getElementById('chatContainer');
            const messageDiv = document.createElement('div');
            messageDiv.className = `alert ${sender === 'user' ? 'alert-primary' : 'alert-secondary'} mb-2`;
            messageDiv.innerHTML = `
                <strong>${sender === 'user' ? 'Tú' : 'IA'}:</strong><br>
                ${message.replace(/\\n/g, '<br>')}
            `;
            chatContainer.appendChild(messageDiv);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
        // Drag and drop
        const uploadArea = document.querySelector('.upload-area');
        
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.style.borderColor = '#0056b3';
            this.style.background = '#e3f2fd';
        });
        
        uploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.style.borderColor = '#007bff';
            this.style.background = '#f8f9fa';
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            this.style.borderColor = '#007bff';
            this.style.background = '#f8f9fa';
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                document.getElementById('fileInput').files = files;
            }
        });
    </script>
</body>
</html>'''
    
    with open(f'{templates_dir}/index.html', 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    # Template del dashboard
    dashboard_html = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - PWN AI Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-robot"></i> PWN AI Analyzer - Dashboard
            </a>
        </div>
    </nav>

    <div class="container mt-4">
        <h2><i class="fas fa-chart-line"></i> Dashboard de Análisis</h2>
        
        <div class="row mt-4">
            {% for analysis_id, data in analyses.items() %}
            <div class="col-md-4 mb-3">
                <div class="card">
                    <div class="card-header">
                        <h6>{{ data.filename }}</h6>
                        <small class="text-muted">{{ data.timestamp }}</small>
                    </div>
                    <div class="card-body">
                        <p><strong>Estado:</strong> 
                            <span class="badge bg-{% if data.status == 'completed' %}success{% elif data.status == 'error' %}danger{% else %}warning{% endif %}">
                                {{ data.status }}
                            </span>
                        </p>
                        
                        {% if data.status == 'completed' and data.results %}
                        <p><strong>Archivos:</strong> {{ data.results.total_files }}</p>
                        <p><strong>Flags:</strong> {{ data.results.total_flags }}</p>
                        <a href="/download/{{ analysis_id }}" class="btn btn-sm btn-primary">
                            <i class="fas fa-download"></i> Descargar
                        </a>
                        {% endif %}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>'''
    
    with open(f'{templates_dir}/dashboard.html', 'w', encoding='utf-8') as f:
        f.write(dashboard_html)

if __name__ == '__main__':
    # Crear templates
    create_templates()
    
    print("🌐 PWN AI Analyzer Web Interface")
    print("=" * 40)
    print("Iniciando servidor web...")
    print("Accede a: http://localhost:5000")
    print("Dashboard: http://localhost:5000/dashboard")
    
    app.run(debug=True, host='0.0.0.0', port=5001)