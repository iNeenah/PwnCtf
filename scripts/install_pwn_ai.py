#!/usr/bin/env python3
"""
Automatic installer for PWN AI Analyzer
Installs all necessary dependencies and sets up the environment
"""

import subprocess
import sys
import os
import platform
import json
from pathlib import Path

class PWNAIInstaller:
    def __init__(self):
        self.system = platform.system()
        self.python_version = sys.version_info
        self.errors = []
        self.warnings = []
        
    def check_python_version(self):
        """Check Python version compatibility"""
        print("Checking Python version...")
        
        if self.python_version < (3, 8):
            self.errors.append("Python 3.8 or higher is required")
            return False
            
        print(f"Python {sys.version} detected - OK")
        return True
    
    def install_pip_packages(self):
        """Install Python packages from requirements.txt"""
        print("\nInstalling Python dependencies...")
        
        # Core packages
        core_packages = [
            "pwntools>=4.8.0",
            "requests>=2.28.0",
            "flask>=2.2.0",
            "flask-cors>=3.0.10",
        ]
        
        # Optional packages
        optional_packages = [
            "google-generativeai>=0.3.0",
            "capstone>=4.0.2",
            "unicorn>=2.0.0",
            "ropgadget>=6.7",
            "python-magic>=0.4.27",
        ]
        
        success_count = 0
        
        # Install core packages
        for package in core_packages:
            if self.install_package(package):
                success_count += 1
            else:
                self.errors.append(f"Failed to install core package: {package}")
        
        # Install optional packages
        for package in optional_packages:
            if self.install_package(package):
                success_count += 1
            else:
                self.warnings.append(f"Optional package not installed: {package}")
        
        print(f"\nInstalled {success_count} packages successfully")
        return len(self.errors) == 0
    
    def install_package(self, package):
        """Install a single package with pip"""
        try:
            print(f"Installing {package}...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"  {package} - OK")
                return True
            else:
                print(f"  {package} - FAILED")
                print(f"  Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"  {package} - TIMEOUT")
            return False
        except Exception as e:
            print(f"  {package} - ERROR: {e}")
            return False
    
    def install_system_tools(self):
        """Install system tools based on OS"""
        print(f"\nInstalling system tools for {self.system}...")
        
        if self.system == "Linux":
            return self.install_linux_tools()
        elif self.system == "Darwin":  # macOS
            return self.install_macos_tools()
        elif self.system == "Windows":
            return self.install_windows_tools()
        else:
            self.warnings.append(f"Unsupported system: {self.system}")
            return True
    
    def install_linux_tools(self):
        """Install Linux system tools"""
        tools = [
            "binutils",
            "gdb", 
            "gcc",
            "g++",
            "make",
            "curl",
            "git"
        ]
        
        # Try different package managers
        if self.command_exists("apt-get"):
            cmd = ["sudo", "apt-get", "install", "-y"] + tools
        elif self.command_exists("yum"):
            cmd = ["sudo", "yum", "install", "-y"] + tools
        elif self.command_exists("pacman"):
            cmd = ["sudo", "pacman", "-S", "--noconfirm"] + tools
        else:
            self.warnings.append("No supported package manager found")
            return True
        
        try:
            print("Installing system tools (requires sudo)...")
            result = subprocess.run(cmd, timeout=600)
            if result.returncode == 0:
                print("System tools installed successfully")
                return True
            else:
                self.warnings.append("Some system tools may not have been installed")
                return True
        except Exception as e:
            self.warnings.append(f"Error installing system tools: {e}")
            return True
    
    def install_macos_tools(self):
        """Install macOS system tools"""
        if not self.command_exists("brew"):
            print("Homebrew not found. Please install Homebrew first:")
            print('  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
            self.warnings.append("Homebrew required for macOS installation")
            return True
        
        tools = ["binutils", "gdb", "gcc"]
        
        for tool in tools:
            try:
                subprocess.run(["brew", "install", tool], timeout=300)
                print(f"  {tool} - OK")
            except Exception as e:
                self.warnings.append(f"Failed to install {tool}: {e}")
        
        return True
    
    def install_windows_tools(self):
        """Install Windows system tools"""
        print("For Windows, please install:")
        print("  1. Windows Subsystem for Linux (WSL2)")
        print("  2. Ubuntu from Microsoft Store")
        print("  3. Run this installer inside WSL")
        
        self.warnings.append("Windows requires WSL for full functionality")
        return True
    
    def command_exists(self, command):
        """Check if a command exists in PATH"""
        try:
            subprocess.run([command, "--version"], 
                         capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("\nCreating directories...")
        
        directories = [
            "analysis_workspace",
            "challenges", 
            "exploits",
            "docs",
            ".github/workflows"
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                print(f"  {directory}/ - OK")
            except Exception as e:
                self.warnings.append(f"Failed to create {directory}: {e}")
        
        return True
    
    def create_config_files(self):
        """Create configuration files"""
        print("\nCreating configuration files...")
        
        # Create basic config
        config = {
            "analysis": {
                "timeout": 30,
                "max_memory": 1024,
                "parallel_jobs": 4
            },
            "ai": {
                "provider": "gemini",
                "model": "gemini-pro",
                "temperature": 0.1
            },
            "web": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False
            }
        }
        
        try:
            with open("config.json", "w") as f:
                json.dump(config, f, indent=2)
            print("  config.json - OK")
        except Exception as e:
            self.warnings.append(f"Failed to create config.json: {e}")
        
        # Create .env template
        env_template = """# PWN AI Analyzer Environment Variables
# Copy this file to .env and fill in your values

# Gemini AI API Key (optional but recommended)
GEMINI_API_KEY=your_gemini_api_key_here

# Debug mode (0 or 1)
PWN_DEBUG=0

# Analysis timeout in seconds
PWN_TIMEOUT=30

# Maximum memory usage in MB
PWN_MAX_MEMORY=1024

# Web interface settings
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=0
"""
        
        try:
            with open(".env.template", "w") as f:
                f.write(env_template)
            print("  .env.template - OK")
        except Exception as e:
            self.warnings.append(f"Failed to create .env.template: {e}")
        
        return True
    
    def verify_installation(self):
        """Verify that installation was successful"""
        print("\nVerifying installation...")
        
        # Test imports
        test_imports = [
            ("pwn", "pwntools"),
            ("requests", "requests"),
            ("flask", "flask"),
        ]
        
        for module, package in test_imports:
            try:
                __import__(module)
                print(f"  {package} - OK")
            except ImportError:
                self.errors.append(f"Failed to import {package}")
        
        # Test main modules
        test_files = [
            "pwn_ai_analyzer.py",
            "advanced_pwn_solver.py",
            "web_pwn_analyzer.py"
        ]
        
        for file in test_files:
            if os.path.exists(file):
                print(f"  {file} - OK")
            else:
                self.errors.append(f"Missing file: {file}")
        
        return len(self.errors) == 0
    
    def print_summary(self):
        """Print installation summary"""
        print("\n" + "="*60)
        print("INSTALLATION SUMMARY")
        print("="*60)
        
        if self.errors:
            print(f"\nERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  - {error}")
        
        if self.warnings:
            print(f"\nWARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        if not self.errors:
            print("\nINSTALLATION SUCCESSFUL!")
            print("\nNext steps:")
            print("  1. Set up your Gemini API key in .env file")
            print("  2. Run: python demo_simple_pwn_ai.py")
            print("  3. Try: python pwn_ai_analyzer.py --help")
            print("  4. Start web interface: python web_pwn_analyzer.py")
            
            print("\nUsage examples:")
            print("  python pwn_ai_analyzer.py ./challenge_directory/")
            print("  python advanced_pwn_solver.py ./binary_file")
            print("  python web_pwn_analyzer.py")
        else:
            print(f"\nINSTALLATION FAILED with {len(self.errors)} errors")
            print("Please fix the errors above and try again")
        
        print("="*60)
    
    def run(self):
        """Run the complete installation process"""
        print("PWN AI Analyzer - Automatic Installer")
        print("="*60)
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Installing Python packages", self.install_pip_packages),
            ("Installing system tools", self.install_system_tools),
            ("Creating directories", self.create_directories),
            ("Creating configuration files", self.create_config_files),
            ("Verifying installation", self.verify_installation),
        ]
        
        for step_name, step_func in steps:
            print(f"\n[STEP] {step_name}")
            if not step_func():
                print(f"[FAILED] {step_name}")
                break
            print(f"[OK] {step_name}")
        
        self.print_summary()
        return len(self.errors) == 0

def main():
    """Main installation function"""
    installer = PWNAIInstaller()
    success = installer.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()