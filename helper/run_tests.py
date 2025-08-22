#!/usr/bin/env python3
"""
Test runner for the Databricks authentication system.

This script provides a convenient way to run tests with different options.
"""

import sys
import os
import subprocess
import argparse

def run_tests(test_path=None, verbose=False, coverage=False, html_report=False):
    """
    Run the test suite.
    
    Args:
        test_path: Specific test file or directory to run
        verbose: Run tests in verbose mode
        coverage: Run tests with coverage reporting
        html_report: Generate HTML coverage report
    """
    # Add src to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    cmd = ['python', '-m', 'pytest']
    
    if test_path:
        cmd.append(test_path)
    else:
        cmd.append('tests/')
    
    if verbose:
        cmd.append('-v')
    
    if coverage:
        cmd.extend(['--cov=databricks.anyauth', '--cov-report=term-missing'])
        
        if html_report:
            cmd.extend(['--cov-report=html'])
    
    print(f"Running: {' '.join(cmd)}")
    print("-" * 80)
    
    result = subprocess.run(cmd, cwd=os.path.dirname(__file__))
    return result.returncode

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run Databricks authentication tests')
    parser.add_argument('test_path', nargs='?', help='Specific test file or directory to run')
    parser.add_argument('-v', '--verbose', action='store_true', help='Run tests in verbose mode')
    parser.add_argument('-c', '--coverage', action='store_true', help='Run tests with coverage reporting')
    parser.add_argument('--html-report', action='store_true', help='Generate HTML coverage report')
    
    args = parser.parse_args()
    
    exit_code = run_tests(
        test_path=args.test_path,
        verbose=args.verbose,
        coverage=args.coverage,
        html_report=args.html_report
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
