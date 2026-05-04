#!/usr/bin/env python3

import sys
import os

filename = sys.argv[1]

destdir = os.environ.get('DESTDIR')
if destdir:
    filename = destdir + filename

with open(filename, 'r', encoding='utf-8') as f:
    lines = f.readlines()

filtered_lines = [
    line for line in lines
    if "SWTPM_TEST_UNINSTALLED=1" not in line
]

with open(filename, 'w', encoding='utf-8') as f:
    f.writelines(filtered_lines)
