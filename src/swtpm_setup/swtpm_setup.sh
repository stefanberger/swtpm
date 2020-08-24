#!/usr/bin/env bash

python3 -c "
import sys;
from py_swtpm_setup.swtpm_setup import main

sys.argv.pop(0)
sys.argv[0]='$0'
main()" \
- "$@"
