#!/bin/bash
# Extract IOCTL codes from IntelPMT.sys using objdump
set -euo pipefail

DRIVER="ghidra/drivers/IntelPMT.sys"
OUTPUT="ghidra/notes/IntelPMT-objdump-analysis.txt"

echo "[*] Analyzing IntelPMT.sys with objdump..."
echo "Driver: $DRIVER"
echo "Output: $OUTPUT"
echo

{
    echo "=== INTELPMT.SYS STATIC ANALYSIS ==="
    echo "Generated: $(date)"
    echo
    
    echo "=== FILE INFO ==="
    file "$DRIVER"
    echo "Size: $(ls -lh "$DRIVER" | awk '{print $5}')"
    echo "MD5: $(md5 -q "$DRIVER")"
    echo
    
    echo "=== SECTIONS ==="
    objdump -h "$DRIVER"
    echo
    
    echo "=== IMPORTS (ntoskrnl.exe) ==="
    objdump -p "$DRIVER" | awk '/DLL Name: ntoskrnl.exe/,/DLL Name:/' | grep -E "^\s+[0-9]+"
    echo
    
    echo "=== DANGEROUS APIS ==="
    echo "Memory Management:"
    objdump -p "$DRIVER" | grep -iE "Mm(Map|Unmap|Get|Copy|Allocate)" || echo "  None found"
    echo
    echo "MSR Access:"
    objdump -p "$DRIVER" | grep -iE "(readmsr|writemsr|wrmsr)" || echo "  None found"
    echo
    
    echo "=== KEY STRINGS ==="
    echo "Device/IOCTL related:"
    strings "$DRIVER" | grep -iE "(device|ioctl|interface)" | head -20
    echo
    echo "Intel functions:"
    strings "$DRIVER" | grep "^Intel" | head -20
    echo
    
    echo "=== ANALYSIS COMPLETE ==="
    echo "Next: Load in Ghidra or IDA for full reverse engineering"
} > "$OUTPUT"

cat "$OUTPUT"
echo
echo "[+] Analysis saved to: $OUTPUT"
