#!/usr/bin/env python3
"""
Domain OSINT CLI.

A command-line tool for domain intelligence gathering.
"""

import argparse
import json
import sys
from pathlib import Path

from src.osint.engine import DomainOSINT
from src.reports.generator import ReportGenerator


def analyze_command(args):
    """Execute the analyze command."""
    engine = DomainOSINT()
    
    print(f"[*] Analyzing domain: {args.domain}")
    
    try:
        result = engine.analyze(args.domain)
        
        print(f"\n[+] Analysis complete for {args.domain}\n")
        
        # DNS Records
        print("=== DNS Records ===")
        for rtype, records in result.get('dns', {}).items():
            if records:
                print(f"  {rtype}: {', '.join(records)}")
        
        # SSL Info
        print("\n=== SSL Certificate ===")
        ssl_info = result.get('ssl', {})
        if 'subject' in ssl_info:
            print(f"  Subject: {ssl_info['subject']}")
            print(f"  Issuer: {ssl_info.get('issuer', 'N/A')}")
        
        # Technologies
        print("\n=== Technologies ===")
        for tech in result.get('technologies', []):
            print(f"  - {tech}")
        
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2))
            print(f"\n[+] Results saved to: {args.output}")
    
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def report_command(args):
    """Execute the report command."""
    engine = DomainOSINT()
    generator = ReportGenerator()
    
    print(f"[*] Generating report for: {args.domain}")
    
    try:
        result = engine.analyze(args.domain)
        output = generator.generate(result, args.output)
        print(f"[+] Report generated: {output}")
    
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Domain OSINT Tool"
    )
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Full domain analysis')
    analyze_parser.add_argument('domain', help='Domain to analyze')
    analyze_parser.add_argument('--output', '-o', help='Output file')
    analyze_parser.set_defaults(func=analyze_command)
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate HTML report')
    report_parser.add_argument('domain', help='Domain to analyze')
    report_parser.add_argument('--output', '-o', default='report.html')
    report_parser.set_defaults(func=report_command)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == '__main__':
    main()
