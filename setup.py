#!/usr/bin/env python3
"""
Setup script for PWN AI Analyzer
Installs the package and its dependencies
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Advanced AI-powered CTF challenge analysis system"

# Read requirements
def read_requirements(filename):
    try:
        with open(filename, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []

setup(
    name="pwn-ai-analyzer",
    version="2.0.0",
    author="PWN AI Team",
    author_email="contact@pwnai.com",
    description="Advanced AI-powered CTF challenge analysis system",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/iNeenah/PwnCtf",
    project_urls={
        "Bug Reports": "https://github.com/iNeenah/PwnCtf/issues",
        "Source": "https://github.com/iNeenah/PwnCtf",
        "Documentation": "https://github.com/iNeenah/PwnCtf/tree/main/docs",
    },
    packages=find_packages(exclude=["tests*", "docs*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Education :: Computer Aided Instruction (CAI)",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="ctf pwn security ai analysis automation hacking",
    python_requires=">=3.8",
    install_requires=[
        "pwntools>=4.8.0",
        "requests>=2.28.0",
        "flask>=2.2.0",
        "flask-cors>=3.0.10",
        "google-generativeai>=0.3.0",
        "capstone>=4.0.2",
        "unicorn>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
        ],
        "web": [
            "werkzeug>=2.2.0",
            "jinja2>=3.1.0",
        ],
        "analysis": [
            "ropgadget>=6.7",
            "python-magic>=0.4.27",
        ],
    },
    entry_points={
        "console_scripts": [
            "pwn-ai-analyzer=pwn_ai_analyzer:main",
            "pwn-solver=advanced_pwn_solver:main",
            "pwn-web=web_pwn_analyzer:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.json", "*.yaml"],
        "docs": ["*.md"],
        "examples": ["*"],
    },
    zip_safe=False,
    platforms=["any"],
)