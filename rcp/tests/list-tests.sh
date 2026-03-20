#!/bin/bash
# Discover all test subdirectories
# Output: space-separated list of test directory names
ls -d */ 2>/dev/null | sed 's|/||g' | sort | tr '\n' ' ' | sed 's/ $//'
