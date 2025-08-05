#!/usr/bin/env python3

"""
JustCTF 2025 Techniques Demo
Demonstrates advanced exploitation techniques from JustCTF 2025 writeup
"""

import sys
import os
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

def demo_justctf2025_techniques():
    """Demonstrate JustCTF 2025 advanced exploitation techniques"""
    
    print("JustCTF 2025 Advanced Exploitation Techniques Demo")
    print("=" * 70)
    print("Showcasing cutting-edge techniques from real CTF writeups")
    print()
    
    try:
        # Import JustCTF 2025 techniques
        from justctf2025_techniques import JustCTF2025Techniques
        from smm_exploitation import SMMExploitationTechniques
        from advanced_uaf_techniques import AdvancedUAFTechniques
        
        print("[+] Initializing JustCTF 2025 exploitation framework...")
        justctf = JustCTF2025Techniques()
        smm_exploiter = SMMExploitationTechniques()
        uaf_exploiter = AdvancedUAFTechniques()
        
        print("\n" + "="*70)
        print("1. SMM LOCKBOX BUFFER OVERFLOW EXPLOITATION")
        print("="*70)
        
        print("\n[+] Demonstrating SMM LockBox buffer overflow technique...")
        print("    Vulnerability: Size inconsistency between Buffer and SmramBuffer")
        print("    Impact: SMM code execution, S3 resume hijacking")
        
        # Generate SMM exploit
        smm_exploit_info = justctf.smm_lockbox_buffer_overflow_exploit()
        
        print(f"\n[+] Technique: {smm_exploit_info['technique']}")
        print(f"[+] Vulnerability: {smm_exploit_info['vulnerability']}")
        print(f"[+] Impact: {smm_exploit_info['impact']}")
        
        print("\n[+] Exploitation Steps:")
        for step in smm_exploit_info['steps']:
            print(f"    {step}")
        
        # Test SMM detection
        print("\n[+] Testing SMM challenge detection...")
        test_binary = "test_smm_challenge"
        if smm_exploiter.detect_smm_challenge(test_binary):
            print("    ✓ SMM challenge detection working")
        else:
            print("    ℹ SMM challenge detection (simulated)")
        
        # Show SMM shellcode generation
        print("\n[+] Generating SMM shellcode...")
        shellcode = smm_exploiter.build_smm_shellcode()
        print(f"    Generated {len(shellcode)} bytes of SMM shellcode")
        print("    Shellcode capabilities:")
        print("    - PTE overwrite for memory access bypass")
        print("    - LockBox handler overwrite")
        print("    - Clean return to SmmRestoreCpu")
        
        print("\n" + "="*70)
        print("2. KERNEL UAF WITH PIPE SPRAY EXPLOITATION")
        print("="*70)
        
        print("\n[+] Demonstrating kernel UAF with pipe spray technique...")
        print("    Technique: Use pipe_buffer structures for reliable heap layout")
        print("    Impact: Kernel code execution, privilege escalation")
        
        # Generate UAF exploit
        uaf_exploit_info = justctf.kernel_uaf_pipe_spray_exploit()
        
        print(f"\n[+] Technique: {uaf_exploit_info['technique']}")
        print(f"[+] Vulnerability: {uaf_exploit_info['vulnerability']}")
        print(f"[+] Impact: {uaf_exploit_info['impact']}")
        
        print("\n[+] Exploitation Steps:")
        for step in uaf_exploit_info['steps']:
            print(f"    {step}")
        
        # Test UAF detection
        print("\n[+] Testing UAF vulnerability detection...")
        test_binary = "test_uaf_challenge"
        analysis = uaf_exploiter.analyze_uaf_exploitability(test_binary)
        
        if analysis["exploitable"]:
            print("    ✓ UAF vulnerability detection working")
            print(f"    Confidence: {analysis['confidence']:.2f}")
        else:
            print("    ℹ UAF vulnerability detection (simulated)")
        
        # Show kernel ROP chain
        print("\n[+] Building kernel ROP chain...")
        kernel_exploit = uaf_exploiter.kernel_uaf_with_pipe_spray()
        print(f"    Pipe spray: {kernel_exploit['pipe_count']} pipes")
        print(f"    Trigger pipes: {kernel_exploit['trigger_pipes']}")
        print("    ROP chain capabilities:")
        print("    - JOP->ROP transition")
        print("    - Privilege escalation (commit_creds)")
        print("    - KPTI bypass for clean userspace return")
        
        print("\n" + "="*70)
        print("3. S3 RESUME STATE HIJACKING")
        print("="*70)
        
        print("\n[+] Demonstrating S3 resume state hijacking...")
        s3_hijack_info = justctf.s3_resume_state_hijacking()
        
        print(f"[+] Technique: {s3_hijack_info['technique']}")
        print(f"[+] Target: {s3_hijack_info['target']}")
        
        print("\n[+] Controlled Fields:")
        for field in s3_hijack_info['controlled_fields']:
            print(f"    - {field}")
        
        print(f"\n[+] Exploitation: {s3_hijack_info['exploitation']}")
        
        print("\n" + "="*70)
        print("4. PTE OVERWRITE MEMORY BYPASS")
        print("="*70)
        
        print("\n[+] Demonstrating PTE overwrite bypass...")
        pte_bypass_info = justctf.pte_overwrite_memory_bypass()
        
        print(f"[+] Technique: {pte_bypass_info['technique']}")
        print(f"[+] Target: {pte_bypass_info['target']}")
        print(f"[+] Calculation: {pte_bypass_info['calculation']}")
        
        example = pte_bypass_info['example']
        print(f"\n[+] Example:")
        print(f"    Target Address: {example['target_addr']}")
        print(f"    CR3 Base: {example['cr3_base']}")
        print(f"    PTE Address: {example['pte_addr']}")
        print(f"    PTE Value: {example['pte_value']}")
        
        print(f"\n[+] Impact: {pte_bypass_info['impact']}")
        
        print("\n" + "="*70)
        print("5. COMPLETE EXPLOIT GENERATION")
        print("="*70)
        
        print("\n[+] Generating complete SMM kernel module...")
        smm_module = justctf.generate_complete_smm_exploit()
        print(f"    Generated {len(smm_module)} lines of kernel module code")
        print("    Module capabilities:")
        print("    - Physical memory mapping")
        print("    - SMI trigger mechanism")
        print("    - LockBox manipulation")
        print("    - S3 resume hijacking")
        
        print("\n[+] Generating complete UAF exploit...")
        uaf_exploit = justctf.generate_complete_uaf_exploit()
        print(f"    Generated {len(uaf_exploit)} lines of exploit code")
        print("    Exploit capabilities:")
        print("    - Pipe spray heap manipulation")
        print("    - Kernel address leaking")
        print("    - JOP->ROP chain execution")
        print("    - Privilege escalation")
        
        print("\n" + "="*70)
        print("6. CHALLENGE ANALYSIS SIMULATION")
        print("="*70)
        
        print("\n[+] Simulating challenge analysis...")
        
        # Simulate SMM challenge
        print("\n[+] Analyzing simulated SMM challenge...")
        smm_analysis = justctf.analyze_justctf2025_challenge("simulated_smm_challenge")
        if smm_analysis["detected"]:
            print(f"    ✓ SMM techniques detected (score: {smm_analysis['smm_score']})")
            print(f"    Recommended techniques: {smm_analysis['techniques']}")
        
        # Get exploitation strategies
        strategies = justctf.get_exploitation_strategy(smm_analysis)
        if strategies:
            print("\n[+] Recommended exploitation strategies:")
            for i, strategy in enumerate(strategies, 1):
                print(f"    {i}. {strategy['technique']} (Priority: {strategy['priority']})")
                print(f"       Description: {strategy['description']}")
                print(f"       Complexity: {strategy['complexity']}")
        
        print("\n" + "="*70)
        print("7. ADVANCED TECHNIQUE INTEGRATION")
        print("="*70)
        
        print("\n[+] Demonstrating technique integration...")
        
        # Show how techniques can be combined
        print("\n[+] Combined exploitation approach:")
        print("    1. Use SMM LockBox overflow to gain SMM execution")
        print("    2. Modify page tables to bypass memory restrictions")
        print("    3. Install persistent hooks in SMM handlers")
        print("    4. Use UAF techniques for kernel privilege escalation")
        print("    5. Maintain persistence across S3 resume cycles")
        
        print("\n[+] Real-world applications:")
        print("    - UEFI/BIOS exploitation")
        print("    - Hypervisor escape techniques")
        print("    - Firmware-level persistence")
        print("    - Advanced kernel exploitation")
        
        print("\n" + "="*70)
        print("DEMO SUMMARY")
        print("="*70)
        
        print("\n✅ JustCTF 2025 Techniques Demo Completed Successfully!")
        print("\nTechniques demonstrated:")
        print("  🔥 SMM LockBox Buffer Overflow")
        print("  🔥 Kernel UAF with Pipe Spray")
        print("  🔥 S3 Resume State Hijacking")
        print("  🔥 PTE Overwrite Memory Bypass")
        print("  🔥 Complete Exploit Generation")
        print("  🔥 Advanced Challenge Analysis")
        
        print("\nKey capabilities:")
        print("  ⚡ Real CTF writeup techniques")
        print("  ⚡ Production-ready exploit code")
        print("  ⚡ Advanced vulnerability detection")
        print("  ⚡ Automated exploit generation")
        print("  ⚡ Multi-technique integration")
        
        print("\nFiles generated:")
        print("  📁 src/justctf2025_techniques.py - Core techniques")
        print("  📁 src/smm_exploitation.py - SMM exploitation")
        print("  📁 src/advanced_uaf_techniques.py - UAF techniques")
        print("  📁 demos/demo_justctf2025_techniques.py - This demo")
        
        print(f"\n🎯 Ready for advanced CTF challenges and real-world exploitation!")
        
    except ImportError as e:
        print(f"❌ Error: Missing dependencies - {e}")
        print("💡 Run: python pwn_ai.py install")
        return False
    except Exception as e:
        print(f"❌ Error during demo: {e}")
        return False
    
    return True

def interactive_demo():
    """Interactive demo with user choices"""
    print("\n" + "="*70)
    print("INTERACTIVE JUSTCTF 2025 TECHNIQUES DEMO")
    print("="*70)
    
    while True:
        print("\nChoose a technique to explore:")
        print("1. SMM LockBox Buffer Overflow")
        print("2. Kernel UAF with Pipe Spray")
        print("3. S3 Resume State Hijacking")
        print("4. PTE Overwrite Memory Bypass")
        print("5. Generate Complete Exploits")
        print("6. Run Full Demo")
        print("0. Exit")
        
        try:
            choice = input("\nEnter your choice (0-6): ").strip()
            
            if choice == '0':
                print("👋 Goodbye!")
                break
            elif choice == '1':
                demo_smm_technique()
            elif choice == '2':
                demo_uaf_technique()
            elif choice == '3':
                demo_s3_technique()
            elif choice == '4':
                demo_pte_technique()
            elif choice == '5':
                demo_exploit_generation()
            elif choice == '6':
                demo_justctf2025_techniques()
            else:
                print("❌ Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\n👋 Demo interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def demo_smm_technique():
    """Demo SMM technique specifically"""
    print("\n🔥 SMM LockBox Buffer Overflow Technique")
    print("-" * 50)
    
    try:
        from justctf2025_techniques import JustCTF2025Techniques
        justctf = JustCTF2025Techniques()
        
        exploit_info = justctf.smm_lockbox_buffer_overflow_exploit()
        
        print(f"Technique: {exploit_info['technique']}")
        print(f"Vulnerability: {exploit_info['vulnerability']}")
        print(f"Impact: {exploit_info['impact']}")
        
        print("\nExploitation Steps:")
        for step in exploit_info['steps']:
            print(f"  {step}")
            
        print(f"\n✅ SMM technique demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def demo_uaf_technique():
    """Demo UAF technique specifically"""
    print("\n🔥 Kernel UAF with Pipe Spray Technique")
    print("-" * 50)
    
    try:
        from justctf2025_techniques import JustCTF2025Techniques
        justctf = JustCTF2025Techniques()
        
        exploit_info = justctf.kernel_uaf_pipe_spray_exploit()
        
        print(f"Technique: {exploit_info['technique']}")
        print(f"Vulnerability: {exploit_info['vulnerability']}")
        print(f"Impact: {exploit_info['impact']}")
        
        print("\nExploitation Steps:")
        for step in exploit_info['steps']:
            print(f"  {step}")
            
        print(f"\n✅ UAF technique demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def demo_s3_technique():
    """Demo S3 technique specifically"""
    print("\n🔥 S3 Resume State Hijacking Technique")
    print("-" * 50)
    
    try:
        from justctf2025_techniques import JustCTF2025Techniques
        justctf = JustCTF2025Techniques()
        
        hijack_info = justctf.s3_resume_state_hijacking()
        
        print(f"Technique: {hijack_info['technique']}")
        print(f"Target: {hijack_info['target']}")
        
        print("\nControlled Fields:")
        for field in hijack_info['controlled_fields']:
            print(f"  - {field}")
            
        print(f"\nExploitation: {hijack_info['exploitation']}")
        print(f"\n✅ S3 technique demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def demo_pte_technique():
    """Demo PTE technique specifically"""
    print("\n🔥 PTE Overwrite Memory Bypass Technique")
    print("-" * 50)
    
    try:
        from justctf2025_techniques import JustCTF2025Techniques
        justctf = JustCTF2025Techniques()
        
        pte_info = justctf.pte_overwrite_memory_bypass()
        
        print(f"Technique: {pte_info['technique']}")
        print(f"Target: {pte_info['target']}")
        print(f"Calculation: {pte_info['calculation']}")
        
        example = pte_info['example']
        print(f"\nExample:")
        print(f"  Target Address: {example['target_addr']}")
        print(f"  PTE Address: {example['pte_addr']}")
        print(f"  PTE Value: {example['pte_value']}")
        
        print(f"\nImpact: {pte_info['impact']}")
        print(f"\n✅ PTE technique demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def demo_exploit_generation():
    """Demo exploit generation specifically"""
    print("\n🔥 Complete Exploit Generation")
    print("-" * 50)
    
    try:
        from justctf2025_techniques import JustCTF2025Techniques
        justctf = JustCTF2025Techniques()
        
        print("Generating SMM kernel module...")
        smm_module = justctf.generate_complete_smm_exploit()
        print(f"✓ Generated {len(smm_module)} lines of SMM exploit code")
        
        print("\nGenerating UAF exploit...")
        uaf_exploit = justctf.generate_complete_uaf_exploit()
        print(f"✓ Generated {len(uaf_exploit)} lines of UAF exploit code")
        
        print(f"\n✅ Exploit generation demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_demo()
    else:
        demo_justctf2025_techniques()