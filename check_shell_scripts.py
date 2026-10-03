#!/usr/bin/env python3
import os
import re
import subprocess
import argparse

SHEBANG_RE = re.compile(rb'^#!.*sh\b')

def find_shell_scripts(start_dir):
    scripts = []
    for root, _, files in os.walk(start_dir):
        for file in files:
            path = os.path.join(root, file)
            try:
                with open(path, 'rb') as f:
                    first_line = f.readline()
                    if SHEBANG_RE.match(first_line):
                        scripts.append(path)
            except (OSError, UnicodeDecodeError):
                continue
    return scripts

def main():
    parser = argparse.ArgumentParser(
        description="Recursively find shell scripts and run shellcheck on them."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output."
    )
    parser.add_argument(
        "directories", nargs="+",
        help="One or more directories to search."
    )

    args = parser.parse_args()

    for directory in args.directories:
        scripts = find_shell_scripts(directory)
        for script in scripts:
            script_dir = os.path.dirname(script)
            cmd = ["shellcheck"] + os.environ.get('SHELLCHECK_ARGS', '').split() + [os.path.basename(script)]
            if args.verbose:
                print(f"Running: {' '.join(cmd)} (in {script_dir})")
            subprocess.run(cmd, cwd=script_dir)

if __name__ == "__main__":
    main()
