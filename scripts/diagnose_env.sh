#!/bin/bash
# Environment diagnostic for Contiki-NG firmware build setup.
# Output is verbose by design — pipe to a file if needed:
#   bash scripts/diagnose_env.sh > diag.txt 2>&1

set +e  # Don't exit on errors — we WANT to see what's missing

echo "=== 1. CONTIKI-NG LOCATION ==="
find / -name "Makefile.include" -path "*/contiki-ng/*" 2>/dev/null | head -3
find / -name "contiki-ng" -type d 2>/dev/null | head -5
echo "CONTIKI env var: ${CONTIKI:-<not set>}"

echo ""
echo "=== 2. CONTIKI-NG VERSION ==="
for dir in ~/contiki-ng ~/Desktop/contiki-ng /opt/contiki-ng /home/*/contiki-ng; do
    if [ -d "$dir" ]; then
        echo "Found at: $dir"
        (cd "$dir" && git log -1 --oneline 2>/dev/null) || echo "  (not a git repo)"
        echo "--- arch/cpu/ ---"
        ls "$dir/arch/cpu/" 2>/dev/null | head -10
        echo "--- examples/ ---"
        ls "$dir/examples/" 2>/dev/null | head -10
        break
    fi
done

echo ""
echo "=== 3. COMPILERS ==="
msp430-gcc --version 2>/dev/null | head -1 || echo "msp430-gcc NOT installed"
arm-none-eabi-gcc --version 2>/dev/null | head -1 || echo "arm-none-eabi-gcc NOT installed"
gcc --version 2>/dev/null | head -1

echo ""
echo "=== 4. COOJA ==="
which cooja 2>/dev/null || echo "no cooja in PATH"
find / -name "cooja.jar" 2>/dev/null | head -3
find / -name "build.xml" -path "*cooja*" 2>/dev/null | head -3
java -version 2>&1 | head -2

echo ""
echo "=== 5. CRYPTO IN CONTIKI-NG ==="
for dir in ~/contiki-ng ~/Desktop/contiki-ng /opt/contiki-ng; do
    if [ -d "$dir" ]; then
        echo "--- Searching $dir for ECC ---"
        find "$dir" -iname "*ecc*" -o -iname "*micro-ecc*" -o -iname "*uECC*" 2>/dev/null | head -10
        echo "--- SHA-256 sources ---"
        find "$dir" -name "sha256.h" 2>/dev/null | head -5
        find "$dir" -name "sha256.c" 2>/dev/null | head -5
        echo "--- os/lib/ contents ---"
        ls "$dir/os/lib/" 2>/dev/null | head -30
        break
    fi
done

echo ""
echo "=== 6. CBOR IN CONTIKI-NG ==="
for dir in ~/contiki-ng ~/Desktop/contiki-ng /opt/contiki-ng; do
    if [ -d "$dir" ]; then
        find "$dir" -iname "*cbor*" 2>/dev/null | head -10
        break
    fi
done

echo ""
echo "=== 7. EXAMPLE HELLO-WORLD ==="
for dir in ~/contiki-ng ~/Desktop/contiki-ng /opt/contiki-ng; do
    if [ -d "$dir/examples/hello-world" ]; then
        echo "hello-world example at: $dir/examples/hello-world"
        ls "$dir/examples/hello-world/"
        break
    fi
done

echo ""
echo "=== 8. PLATFORMS AVAILABLE ==="
for dir in ~/contiki-ng ~/Desktop/contiki-ng /opt/contiki-ng; do
    if [ -d "$dir/arch/platform" ]; then
        echo "Found platforms in $dir/arch/platform:"
        ls "$dir/arch/platform/"
        break
    fi
done

echo ""
echo "=== 9. SYSTEM ==="
uname -a
lsb_release -a 2>/dev/null
df -h ~ | head -2

echo ""
echo "=== DONE ==="
