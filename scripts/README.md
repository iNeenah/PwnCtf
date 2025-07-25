# Scripts

Utility scripts for installation, setup, and maintenance.

## Available Scripts

### Installation
- **`install_pwn_ai.py`** - Automatic dependency installation and setup

## Usage

### Installation Script
```bash
# From project root
python scripts/install_pwn_ai.py

# Or using main entry point
python pwn_ai.py install
```

### What the Installer Does
1. **Checks Python version** compatibility (3.8+)
2. **Installs Python packages** from requirements.txt
3. **Installs system tools** (binutils, gdb, etc.)
4. **Creates directories** for analysis workspace
5. **Sets up configuration** files and templates
6. **Verifies installation** by testing imports

### Platform Support
- **Linux** - Full support with package manager detection
- **macOS** - Homebrew-based installation
- **Windows** - WSL2 recommended for full functionality

### Troubleshooting
The installer provides detailed error messages and warnings for:
- Missing dependencies
- Permission issues
- Platform-specific problems
- Network connectivity issues

Run with Python 3.8+ for best compatibility.