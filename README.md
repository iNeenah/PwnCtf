# PWN AI Analyzer

**Advanced Automated CTF Challenge Analysis System with AI Integration**

A comprehensive system that combines traditional PWN techniques with artificial intelligence to automatically analyze, detect, and exploit CTF challenges. Features techniques extracted from real writeups by top CTF teams like MindCrafters.

---

## ✨ Features

### 🤖 AI-Powered Analysis
- **Gemini AI Integration** - Contextual understanding and exploit generation
- **Smart Challenge Detection** - Automatically identifies CTF challenge types
- **Intelligent Exploit Creation** - AI-guided payload generation
- **Interactive Chat Interface** - Ask AI about analysis results

### 🏆 MindCrafters Techniques
- **UTF-8 Byte Bypass** - Character vs byte exploitation (Safe Gets)
- **Multi-Stage Format String** - Complex sequential chains (The Goose)
- **Heap Feng Shui** - Controlled memory layout manipulation
- **Advanced Race Conditions** - Precise timing attacks
- **Custom Shellcode Generation** - Optimized payload creation

### 🔧 Core Capabilities
- **Universal File Analysis** - Binaries, source code, web files, archives
- **Automatic Flag Detection** - Advanced pattern matching
- **Vulnerability Scanning** - Buffer overflows, format strings, heap bugs
- **Modern Web Interface** - Drag-and-drop analysis with real-time results
- **Comprehensive Reporting** - Detailed analysis with actionable insights

---

## Quick Start

### 🚀 One-Command Setup
```bash
git clone https://github.com/iNeenah/PwnCtf.git && cd PwnCtf && python pwn_ai.py install
```

### 🎯 Basic Usage
```bash
# Analyze CTF challenges
python pwn_ai.py analyze ./challenges/

# Advanced solver with MindCrafters techniques  
python pwn_ai.py solve ./binary --ai-key your_gemini_key

# Modern web interface
python pwn_ai.py web

# Interactive demonstrations
python pwn_ai.py demo
```

### 🔧 Advanced Usage
```bash
# Direct module access
python src/pwn_ai_analyzer.py ./challenges/
python src/advanced_pwn_solver.py ./binary
python src/web_pwn_analyzer.py

# Specific demonstrations
python demos/demo_mindcrafters_simple.py
python examples/examples.py
```

---

## Project Structure

```
PwnCtf/
├── 📄 pwn_ai.py                 # Unified command-line interface
├── 📁 src/                      # Core source code
│   ├── pwn_ai_analyzer.py       # Main analysis engine with AI
│   ├── advanced_pwn_solver.py   # MindCrafters techniques
│   ├── v8_exploit_tool.py       # Browser exploitation toolkit
│   ├── web_pwn_analyzer.py      # Modern web interface
│   ├── pwn_ctf_tool.py          # Basic PWN utilities
│   └── utils.py                 # Shared utilities
├── 📁 scripts/                  # Installation and setup
│   └── install_pwn_ai.py        # Automatic installer
├── 📁 demos/                    # Interactive demonstrations
│   ├── demo_simple_pwn_ai.py    # Basic demo (no dependencies)
│   ├── demo_mindcrafters_simple.py # MindCrafters techniques
│   └── demo_complete_pwn_ai.py  # Full system demo
├── 📁 examples/                 # Practical examples
│   ├── examples.py              # Basic usage examples
│   ├── v8_examples.py           # Browser exploitation
│   └── *.js                     # Real CTF exploits
├── 📁 docs/                     # Comprehensive documentation
│   ├── INSTALLATION.md          # Setup guide
│   ├── API.md                   # API reference
│   └── TECHNIQUES.md            # MindCrafters techniques
└── 📁 legacy/                   # Previous versions and archives
```

---

## Supported Challenge Types

### Binary Exploitation
- **Buffer Overflow** - Stack and heap based overflows
- **Format String** - Arbitrary read/write primitives
- **ROP Chains** - Return-oriented programming
- **Heap Exploitation** - Modern heap attack techniques

### Web Challenges
- **XSS** - Cross-site scripting detection
- **SQL Injection** - Database attack patterns
- **Command Injection** - OS command execution
- **File Inclusion** - Local and remote file inclusion

### Cryptography
- **Classical Ciphers** - Caesar, Vigenere, substitution
- **Hash Cracking** - MD5, SHA1, bcrypt attacks
- **RSA Attacks** - Factorization and weak key exploitation

---

## MindCrafters Techniques

### UTF-8 Byte Bypass
Exploits the difference between character counting and byte counting in Python firewalls.

```python
# UTF-8 character that takes 3 bytes but counts as 1 character
utf8_char = "ⓣ".encode("utf-8")
payload = utf8_char * 30 + b'\x00' * 190 + p64(win_addr)
```

### Multi-Stage Format String
Complex exploitation chain combining format string leak with buffer overflow.

```python
# Stage 1: Leak stack address
format_payload = f"%{1}$p".encode()
leaked_addr = extract_address(response)

# Stage 2: Calculate shellcode address  
shellcode_addr = leaked_addr + 0x52 + 8

# Stage 3: Buffer overflow with custom shellcode
payload = b'A' * 72 + p64(shellcode_addr) + shellcode
```

### Heap Feng Shui
Controlled heap layout manipulation for reliable exploitation.

```python
# Phase 1: Prepare heap layout
for size in [0x20, 0x30, 0x40, 0x50, 0x60]:
    alloc(size)

# Phase 2: Create controlled fragmentation
for i in [0, 2, 4]:
    free(i)

# Phase 3: Exploit layout
payload = b'A' * 0x18 + p64(0x41) + p64(target_addr)
```

---

## Web Interface

The system includes a modern web interface with:

- **File Upload** - Drag and drop challenge files
- **AI Chat** - Interactive analysis with Gemini AI
- **Real-time Results** - Live analysis progress
- **Exploit Download** - Generated exploits and reports

Access at `http://localhost:5000` after running `python web_pwn_analyzer.py`

---

## API Reference

### PWNAIAnalyzer Class
```python
analyzer = PWNAIAnalyzer(gemini_api_key="your_key")
analyzer.analyze_directory("./challenges/")
analyzer.generate_final_report()
```

### AdvancedPWNSolver Class  
```python
solver = AdvancedPWNSolver(gemini_api_key="your_key")
solver.analyze_binary_comprehensive("./binary")
challenge_type = solver.detect_mindcrafters_challenge_type()
solver.apply_mindcrafters_technique(challenge_type)
```

---

## Configuration

### Environment Variables
```bash
export GEMINI_API_KEY="your_gemini_api_key"
export PWN_DEBUG=1  # Enable debug mode
export PWN_TIMEOUT=30  # Set analysis timeout
```

### Config Files
- `.kiro/settings/mcp.json` - MCP server configuration
- `config.json` - General system configuration

---

## Examples

### Automatic Challenge Analysis
```python
from pwn_ai_analyzer import PWNAIAnalyzer

# Initialize with AI
analyzer = PWNAIAnalyzer(gemini_api_key="your_key")

# Analyze challenge directory
analyzer.analyze_directory("./ctf_2024/")

# Results automatically saved to analysis_workspace/
```

### Manual Technique Application
```python
from advanced_pwn_solver import AdvancedPWNSolver

solver = AdvancedPWNSolver()

# Apply specific technique
if solver.detect_mindcrafters_challenge_type() == "safe_gets_utf8":
    payload = solver.utf8_byte_bypass_technique()
    # Use payload for exploitation
```

---

## Contributing

We welcome contributions from the CTF community:

1. **Fork** the repository
2. **Create** a feature branch
3. **Add** new techniques or improvements  
4. **Test** with real CTF challenges
5. **Submit** a pull request

### Adding New Techniques
1. Implement in `advanced_pwn_solver.py`
2. Add detection patterns in `detect_mindcrafters_challenge_type()`
3. Update technique mapping in `apply_mindcrafters_technique()`
4. Add tests and documentation

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- **MindCrafters CTF Team** - For excellent writeups and techniques
- **pwntools** - Essential PWN toolkit
- **Google Gemini** - AI analysis capabilities
- **CTF Community** - Continuous inspiration and challenges

---

## Support

For questions, issues, or contributions:
- **GitHub Issues** - Bug reports and feature requests
- **Documentation** - Comprehensive guides and examples
- **Community** - Join the CTF automation discussion

**Happy Hacking!**