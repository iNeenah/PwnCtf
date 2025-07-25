# API Reference

## Core Classes

### PWNAIAnalyzer

Main analysis engine with AI integration for automatic CTF challenge analysis.

#### Constructor
```python
PWNAIAnalyzer(gemini_api_key=None)
```

**Parameters:**
- `gemini_api_key` (str, optional): Gemini AI API key for enhanced analysis

**Example:**
```python
from pwn_ai_analyzer import PWNAIAnalyzer

# Basic analyzer
analyzer = PWNAIAnalyzer()

# With AI integration
analyzer = PWNAIAnalyzer(gemini_api_key="your_api_key")
```

#### Methods

##### analyze_directory(directory_path)
Analyzes all files in a directory recursively.

**Parameters:**
- `directory_path` (str): Path to directory containing challenges

**Returns:**
- None (results stored in `self.analysis_results`)

**Example:**
```python
analyzer.analyze_directory("./ctf_challenges/")
```

##### analyze_single_file(file_path)
Analyzes a single file.

**Parameters:**
- `file_path` (str): Path to file to analyze

**Returns:**
- None (results stored in `self.analysis_results`)

**Example:**
```python
analyzer.analyze_single_file("./challenge.bin")
```

##### generate_final_report()
Generates comprehensive analysis report.

**Returns:**
- None (saves report to `analysis_workspace/analysis_report.json`)

**Example:**
```python
analyzer.generate_final_report()
```

---

### AdvancedPWNSolver

Enhanced solver implementing MindCrafters techniques for complex PWN challenges.

#### Constructor
```python
AdvancedPWNSolver(gemini_api_key=None)
```

**Parameters:**
- `gemini_api_key` (str, optional): Gemini AI API key

**Example:**
```python
from advanced_pwn_solver import AdvancedPWNSolver

solver = AdvancedPWNSolver(gemini_api_key="your_key")
```

#### Methods

##### analyze_binary_comprehensive(binary_path)
Performs comprehensive binary analysis.

**Parameters:**
- `binary_path` (str): Path to binary file

**Returns:**
- `bool`: True if analysis successful

**Example:**
```python
if solver.analyze_binary_comprehensive("./challenge"):
    print("Analysis complete")
```

##### detect_mindcrafters_challenge_type()
Detects specific challenge type based on MindCrafters patterns.

**Returns:**
- `str`: Detected challenge type

**Possible Values:**
- `"safe_gets_utf8"` - UTF-8 byte bypass challenge
- `"the_goose_format"` - Format string + buffer overflow
- `"heap_challenge"` - Heap exploitation
- `"race_condition"` - Race condition challenge
- `"unknown"` - Unrecognized pattern

**Example:**
```python
challenge_type = solver.detect_mindcrafters_challenge_type()
print(f"Detected: {challenge_type}")
```

##### apply_mindcrafters_technique(challenge_type)
Applies specific technique based on challenge type.

**Parameters:**
- `challenge_type` (str): Challenge type from detection

**Returns:**
- `bytes` or `bool`: Generated payload or success status

**Example:**
```python
payload = solver.apply_mindcrafters_technique("safe_gets_utf8")
if payload:
    # Use payload for exploitation
    pass
```

---

## Technique-Specific Methods

### UTF-8 Byte Bypass

##### utf8_byte_bypass_technique(max_chars=255)
Implements UTF-8 character vs byte bypass technique.

**Parameters:**
- `max_chars` (int): Maximum character limit to bypass

**Returns:**
- `bytes`: Crafted payload

**Example:**
```python
payload = solver.utf8_byte_bypass_technique(255)
# payload contains UTF-8 characters that exceed byte limit
```

### Format String Exploitation

##### format_string_leak_and_exploit()
Multi-stage format string exploitation.

**Returns:**
- `bytes`: Final exploitation payload

**Example:**
```python
payload = solver.format_string_leak_and_exploit()
# payload contains buffer overflow + shellcode
```

### Heap Feng Shui

##### heap_feng_shui_technique()
Controlled heap layout manipulation.

**Returns:**
- `bool`: Success status

**Example:**
```python
success = solver.heap_feng_shui_technique()
if success:
    print("Heap layout prepared for exploitation")
```

### Race Conditions

##### advanced_race_condition_exploit(num_threads=50)
Precise timing attack using multiple threads.

**Parameters:**
- `num_threads` (int): Number of concurrent threads

**Returns:**
- `tuple`: (success, result)

**Example:**
```python
success, result = solver.advanced_race_condition_exploit(100)
if success:
    print(f"Race condition exploited: {result}")
```

---

## Utility Functions

### File Analysis

##### get_file_info(file_path)
Extracts basic file information.

**Parameters:**
- `file_path` (str): Path to file

**Returns:**
- `dict`: File information including size, permissions, magic bytes

**Example:**
```python
info = analyzer.get_file_info("./binary")
print(f"Size: {info['size']} bytes")
print(f"Magic: {info['magic_bytes']}")
```

##### determine_file_type(file_path, file_info)
Determines file type for analysis routing.

**Parameters:**
- `file_path` (str): Path to file
- `file_info` (dict): File information from `get_file_info()`

**Returns:**
- `str`: File type classification

**Possible Values:**
- `"archive"` - Compressed file
- `"binary"` - Executable binary
- `"source_code"` - Source code file
- `"web_file"` - Web-related file
- `"document"` - Text document
- `"unknown"` - Unrecognized type

### Flag Detection

##### search_flags_in_strings(strings, source_file)
Searches for flags in string list.

**Parameters:**
- `strings` (list): List of strings to search
- `source_file` (str): Source file path for reporting

**Returns:**
- None (flags added to `self.flags_found`)

##### search_flags_in_text(text, source_file)
Searches for flags in text content.

**Parameters:**
- `text` (str): Text content to search
- `source_file` (str): Source file path for reporting

**Returns:**
- None (flags added to `self.flags_found`)

---

## Web API Endpoints

When running `web_pwn_analyzer.py`, the following REST endpoints are available:

### POST /analyze
Upload file for analysis.

**Request:**
- Content-Type: `multipart/form-data`
- Body: File upload

**Response:**
```json
{
  "status": "success",
  "analysis_id": "uuid",
  "message": "Analysis started"
}
```

### GET /results/{analysis_id}
Get analysis results.

**Response:**
```json
{
  "status": "complete",
  "flags_found": [...],
  "vulnerabilities": [...],
  "exploits_generated": [...]
}
```

### POST /chat
Chat with AI about analysis.

**Request:**
```json
{
  "message": "How do I exploit this buffer overflow?",
  "context": "analysis_id"
}
```

**Response:**
```json
{
  "response": "AI response text",
  "suggestions": [...]
}
```

### GET /exploits/{analysis_id}
Download generated exploits.

**Response:**
- Content-Type: `application/zip`
- Body: ZIP file containing exploit scripts

---

## Configuration

### Environment Variables

- `GEMINI_API_KEY` - Gemini AI API key
- `PWN_DEBUG` - Enable debug mode (0/1)
- `PWN_TIMEOUT` - Analysis timeout in seconds
- `PWN_MAX_MEMORY` - Maximum memory usage in MB
- `PWN_PARALLEL_JOBS` - Number of parallel analysis jobs

### Config File Format

```json
{
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
  "techniques": {
    "enabled": [
      "utf8_byte_bypass",
      "format_string_leak_exploit",
      "heap_feng_shui",
      "advanced_race_conditions"
    ]
  }
}
```

---

## Error Handling

### Common Exceptions

#### AnalysisError
Raised when analysis fails.

```python
try:
    analyzer.analyze_single_file("./challenge")
except AnalysisError as e:
    print(f"Analysis failed: {e}")
```

#### TechniqueError
Raised when technique application fails.

```python
try:
    payload = solver.apply_mindcrafters_technique("safe_gets_utf8")
except TechniqueError as e:
    print(f"Technique failed: {e}")
```

#### AIError
Raised when AI integration fails.

```python
try:
    analyzer = PWNAIAnalyzer(gemini_api_key="invalid_key")
except AIError as e:
    print(f"AI setup failed: {e}")
```

---

## Examples

### Complete Analysis Workflow
```python
from pwn_ai_analyzer import PWNAIAnalyzer
from advanced_pwn_solver import AdvancedPWNSolver

# Initialize with AI
analyzer = PWNAIAnalyzer(gemini_api_key="your_key")
solver = AdvancedPWNSolver(gemini_api_key="your_key")

# Analyze challenge directory
analyzer.analyze_directory("./ctf_2024/")

# Process each binary found
for file_path, analysis in analyzer.analysis_results.items():
    if analysis.get("type") == "binary":
        # Use advanced solver for binaries
        if solver.analyze_binary_comprehensive(file_path):
            challenge_type = solver.detect_mindcrafters_challenge_type()
            payload = solver.apply_mindcrafters_technique(challenge_type)
            
            if payload:
                print(f"Exploit generated for {file_path}")

# Generate final report
analyzer.generate_final_report()
```

### Custom Technique Implementation
```python
class CustomSolver(AdvancedPWNSolver):
    def custom_technique(self):
        # Implement custom exploitation technique
        payload = b"custom_payload"
        return payload
    
    def detect_custom_challenge(self):
        # Custom challenge detection logic
        return "custom_challenge_type"

# Use custom solver
solver = CustomSolver()
if solver.detect_custom_challenge() == "custom_challenge_type":
    payload = solver.custom_technique()
```

For more examples, see the `examples/` directory in the repository.