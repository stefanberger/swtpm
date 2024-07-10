#!/usr/bin/env sh

verbose=0

# Check for the -v option to enable verbose output
while getopts "v" opt; do
  case $opt in
    v) verbose=1 ;;
    *) echo "Usage: $0 [-v]" >&2; exit 1 ;;
  esac
done

TESTS_FILE="$(dirname "$0")/tests"
if [ -f "$TESTS_FILE" ]; then
    TESTS=$(cat "$TESTS_FILE")
else
    echo "Error: 'tests' file does not exist."
    exit 1
fi

test_count=0
pass_count=0
skip_count=0
fail_count=0

# Iterate through each test in the TESTS variable
for t in $TESTS; do
  if [ "$verbose" -eq 1 ]; then
    "$(dirname "$0")/$t"
    ret=$?
  else
    output=$("$(dirname "$0")/$t" 2>&1)
    ret=$?
  fi

  test_count=$((test_count + 1))
  case $ret in
    0)
      echo "PASS: $t"
      pass_count=$((pass_count + 1))
      ;;
    77)
      echo "SKIP: $t"
      skip_count=$((skip_count + 1))
      ;;
    *)
      echo "FAIL: $t (exit $ret)"
      fail_count=$((fail_count + 1))
      echo "$output"
      ;;
  esac
done

echo "Summary:"
echo "# TOTAL: $test_count"
echo "# PASS: $pass_count"
echo "# SKIP: $skip_count"
echo "# FAIL: $fail_count"

# Exit with 1 if any test failed
if [ "$fail_count" -gt 0 ]; then
  exit 1
else
  exit 0
fi
