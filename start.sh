#!/usr/bin/env python
"""
start.py - Main entry point for Railway deployment
This handles PORT properly without shell variable issues
"""

import os
import sys
import subprocess

def main():
    # Get PORT from environment
    port = os.environ.get('PORT', '8080')
    
    print(f"=" * 50)
    print(f"🚀 Starting HandoffHub on port {port}")
    print(f"=" * 50)
    
    # Build the Gunicorn command
    cmd = [
        'gunicorn',
        'app:app',
        '--bind', f'0.0.0.0:{port}',
        '--workers', '2',
        '--threads', '4',
        '--timeout', '120',
        '--log-level', 'info',
        '--access-logfile', '-',  # Log to stdout
        '--error-logfile', '-'     # Log errors to stdout
    ]
    
    print(f"📌 Running command: {' '.join(cmd)}")
    
    # Execute Gunicorn
    try:
        result = subprocess.run(cmd)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
