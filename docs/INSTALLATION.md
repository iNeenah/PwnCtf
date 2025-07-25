# Installation Guide

## System Requirements

- **Python 3.8+**
- **Linux/WSL** (recommended for PWN tools)
- **4GB RAM** minimum
- **Internet connection** for AI features

---

## Quick Installation

### Automatic Setup
```bash
git clone https://github.com/iNeenah/PwnCtf.git
cd PwnCtf
python install_pwn_ai.py
```

### Manual Installation

#### 1. Core Dependencies
```bash
pip install pwntools requests flask flask-cors
```

#### 2. AI Integration (Optional)
```bash
pip install google-generativeai
```

#### 3. System Tools (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install binutils gdb radare2 strings
```

#### 4. Optional Tools
```bash
# ROPgadget for ROP chain analysis
pip install ropgadget

# Capstone for disassembly
pip install capstone

# Unicorn for emulation
pip install unicorn
```

---

## Configuration

### Environment Variables
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
export PWN_DEBUG=1  # Enable debug output
export PWN_TIMEOUT=30  # Set analysis timeout
```

### Gemini AI Setup
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Set the environment variable or pass it as parameter

### Web Interface Setup
```bash
# Default configuration
export FLASK_HOST="0.0.0.0"
export FLASK_PORT="5000"
export FLASK_DEBUG=0
```

---

## Verification

### Test Installation
```bash
# Test basic functionality
python pwn_ai_analyzer.py --help

# Test with sample challenge
python demo_simple_pwn_ai.py

# Test web interface
python web_pwn_analyzer.py &
curl http://localhost:5000/health
```

### Test AI Integration
```bash
# Test with Gemini API
python -c "
from pwn_ai_analyzer import PWNAIAnalyzer
analyzer = PWNAIAnalyzer('your_api_key')
print('AI integration working!')
"
```

---

## Docker Installation

### Using Docker
```bash
# Build image
docker build -t pwn-ai-analyzer .

# Run container
docker run -it --rm \
  -v $(pwd):/workspace \
  -p 5000:5000 \
  -e GEMINI_API_KEY="your_key" \
  pwn-ai-analyzer
```

### Docker Compose
```yaml
version: '3.8'
services:
  pwn-ai:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./challenges:/app/challenges
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
```

---

## Troubleshooting

### Common Issues

#### pwntools Installation Failed
```bash
# On Ubuntu/Debian
sudo apt-get install python3-dev gcc

# On macOS
xcode-select --install

# Retry installation
pip install --upgrade pwntools
```

#### Gemini API Not Working
```bash
# Verify API key
python -c "
import google.generativeai as genai
genai.configure(api_key='your_key')
model = genai.GenerativeModel('gemini-pro')
print('API key valid!')
"
```

#### Binary Analysis Tools Missing
```bash
# Install missing tools
sudo apt-get install binutils-multiarch
sudo apt-get install gdb-multiarch

# For ARM analysis
sudo apt-get install gcc-arm-linux-gnueabi
```

#### Web Interface Not Loading
```bash
# Check port availability
netstat -tulpn | grep :5000

# Try different port
python web_pwn_analyzer.py --port 8080

# Check firewall
sudo ufw allow 5000
```

### Debug Mode
```bash
# Enable verbose logging
export PWN_DEBUG=1
export PWN_LOG_LEVEL=DEBUG

# Run with debug output
python pwn_ai_analyzer.py ./challenge --verbose
```

---

## Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
ulimit -n 4096

# Optimize for analysis
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Memory Management
```bash
# For large challenge sets
export PWN_MAX_MEMORY=2048  # MB
export PWN_PARALLEL_JOBS=4
```

---

## Development Setup

### Development Dependencies
```bash
pip install pytest black flake8 mypy
```

### Pre-commit Hooks
```bash
pip install pre-commit
pre-commit install
```

### Testing
```bash
# Run test suite
python -m pytest tests/

# Run specific test
python -m pytest tests/test_analyzer.py

# Coverage report
python -m pytest --cov=pwn_ai_analyzer tests/
```

---

## Platform-Specific Notes

### Windows (WSL)
```bash
# Install WSL2
wsl --install

# Install Ubuntu
wsl --install -d Ubuntu

# Setup in WSL
cd /mnt/c/your/path
python install_pwn_ai.py
```

### macOS
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 binutils gdb

# Install PWN AI
python3 install_pwn_ai.py
```

### ARM64 (Apple Silicon)
```bash
# Use Rosetta for x86 tools
arch -x86_64 pip install pwntools

# Native ARM64 installation
pip install --no-binary pwntools pwntools
```

---

## Next Steps

After installation:

1. **Read Documentation** - Check `docs/` directory
2. **Run Examples** - Try `examples/` challenges
3. **Test Techniques** - Use `demo_mindcrafters_simple.py`
4. **Configure AI** - Set up Gemini API key
5. **Start Analyzing** - Begin with your CTF challenges

For support, check the [GitHub Issues](https://github.com/iNeenah/PwnCtf/issues) page.