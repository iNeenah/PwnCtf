#!/usr/bin/env python3
"""
PWN AI Analyzer - Main Entry Point
Unified command-line interface for all PWN AI tools
"""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def main():
    """Main entry point with subcommands"""
    parser = argparse.ArgumentParser(
        description="PWN AI Analyzer - Advanced CTF Challenge Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze ./challenges/          # Analyze challenge directory
  %(prog)s solve ./binary                 # Use advanced solver
  %(prog)s web                           # Start web interface
  %(prog)s demo                          # Run demonstration
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze challenges')
    analyze_parser.add_argument('target', help='Target file or directory')
    analyze_parser.add_argument('--ai-key', help='Gemini AI API key')
    analyze_parser.add_argument('--output', help='Output directory')
    
    # Solve command
    solve_parser = subparsers.add_parser('solve', help='Advanced PWN solver')
    solve_parser.add_argument('binary', help='Binary file to analyze')
    solve_parser.add_argument('--ai-key', help='Gemini AI API key')
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='0.0.0.0', help='Host address')
    web_parser.add_argument('--port', type=int, default=5000, help='Port number')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run demonstration')
    demo_parser.add_argument('--type', choices=['simple', 'advanced', 'complete'], 
                           default='simple', help='Demo type')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install dependencies')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'analyze':
            from pwn_ai_analyzer import PWNAIAnalyzer
            analyzer = PWNAIAnalyzer(gemini_api_key=args.ai_key)
            
            if os.path.isdir(args.target):
                analyzer.analyze_directory(args.target)
            else:
                analyzer.analyze_single_file(args.target)
            
            analyzer.generate_final_report()
            print(f"Analysis complete! Check analysis_workspace/ for results.")
            
        elif args.command == 'solve':
            from advanced_pwn_solver import AdvancedPWNSolver
            solver = AdvancedPWNSolver(gemini_api_key=args.ai_key)
            
            if solver.analyze_binary_comprehensive(args.binary):
                challenge_type = solver.detect_mindcrafters_challenge_type()
                result = solver.apply_mindcrafters_technique(challenge_type)
                
                if result:
                    print("Exploitation successful with MindCrafters techniques!")
                else:
                    print("Standard exploitation techniques applied.")
            
        elif args.command == 'web':
            from web_pwn_analyzer import app
            print(f"Starting web interface at http://{args.host}:{args.port}")
            app.run(host=args.host, port=args.port, debug=False)
            
        elif args.command == 'demo':
            demo_path = Path(__file__).parent / "demos"
            
            if args.type == 'simple':
                os.system(f"python {demo_path}/demo_simple_pwn_ai.py")
            elif args.type == 'advanced':
                os.system(f"python {demo_path}/demo_advanced_techniques.py")
            elif args.type == 'complete':
                os.system(f"python {demo_path}/demo_complete_pwn_ai.py")
                
        elif args.command == 'install':
            install_script = Path(__file__).parent / "scripts" / "install_pwn_ai.py"
            os.system(f"python {install_script}")
            
    except ImportError as e:
        print(f"Error: Missing dependencies. Run 'python pwn_ai.py install' first.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()