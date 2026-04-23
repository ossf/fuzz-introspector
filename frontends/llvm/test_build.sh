#!/bin/bash -eu
# Quick local tests for FuzzIntrospector.
# Does NOT modify system LLVM headers — all work in temporary directories.
#
# Usage:
#   ./test_build.sh [mode] [llvm-version]
#
#   mode:         all (default) | patch | syntax | e2e
#   llvm-version: 18 | 22 | auto (default — tests every installed version)
#
# Examples:
#   ./test_build.sh              # all tests, all installed LLVM versions
#   ./test_build.sh all 22       # all tests, LLVM 22 only
#   ./test_build.sh e2e 18       # end-to-end, LLVM 18 only

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_FUZZER="$REPO_ROOT/tests/cpp-simple-example-1/fuzzer.cpp"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}PASS${NC}: $*"; }
fail() { echo -e "${RED}FAIL${NC}: $*"; FAILED=$((FAILED+1)); }
info() { echo -e "${YELLOW}INFO${NC}: $*"; }

FAILED=0
MODE="${1:-all}"
VER_ARG="${2:-auto}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Returns the sed pattern for patching InitializePasses.h for a given version.
# Mirrors the logic in patch-llvm.sh (both seds are applied; one is a no-op).
patch_initialize_passes() {
    local h="$1"
    # LLVM 21+: LLVM_ABI visibility macro
    sed -i 's/LLVM_ABI void initializeMIRNamerPass/LLVM_ABI void initializeFuzzIntrospectorPass(PassRegistry \&);\nLLVM_ABI void initializeMIRNamerPass/g' "$h"
    # LLVM 18-20: XRay anchor (renamed in LLVM 21)
    sed -i 's/void initializeXRayInstrumentationPass(PassRegistry[ ]*\&);/void initializeXRayInstrumentationPass(PassRegistry \&);\nvoid initializeFuzzIntrospectorPass(PassRegistry \&);/g' "$h"
}

# Discover which LLVM versions are usable.
available_versions() {
    local vers=()
    for v in 18 19 20 21 22; do
        [[ -d "/usr/lib/llvm-$v/include" ]] && command -v "clang-$v" &>/dev/null && vers+=("$v")
    done
    echo "${vers[@]}"
}

# ---------------------------------------------------------------------------
# Test 1: patch-llvm.sh sed patterns against a real InitializePasses.h
# ---------------------------------------------------------------------------
test_patch() {
    local ver="$1"
    local inc="/usr/lib/llvm-${ver}/include"
    info "[LLVM $ver] Test: patch-llvm.sh injects initializeFuzzIntrospectorPass"

    [[ -f "$inc/llvm/InitializePasses.h" ]] || { info "no InitializePasses.h for LLVM $ver, skipping"; return; }

    local WORK PASSES_H
    WORK=$(mktemp -d)
    PASSES_H="$WORK/InitializePasses.h"
    cp "$inc/llvm/InitializePasses.h" "$PASSES_H"
    patch_initialize_passes "$PASSES_H"

    if grep -q 'initializeFuzzIntrospectorPass' "$PASSES_H"; then
        pass "[LLVM $ver] declaration injected: $(grep 'initializeFuzzIntrospectorPass' "$PASSES_H" | xargs)"
    else
        fail "[LLVM $ver] declaration NOT found in InitializePasses.h after sed"
    fi
    rm -rf "$WORK"
}

# ---------------------------------------------------------------------------
# Test 2: syntax-check FuzzIntrospector.cpp (no object code produced)
# ---------------------------------------------------------------------------
test_syntax() {
    local ver="$1"
    local inc="/usr/lib/llvm-${ver}/include"
    info "[LLVM $ver] Test: syntax-check FuzzIntrospector.cpp"

    command -v "clang-$ver" &>/dev/null || { info "clang-$ver not found, skipping"; return; }
    [[ -f "$inc/llvm/InitializePasses.h" ]] || { info "no headers for LLVM $ver, skipping"; return; }

    local WORK
    WORK=$(mktemp -d)
    mkdir -p "$WORK/llvm"
    cp "$inc/llvm/InitializePasses.h" "$WORK/llvm/"
    patch_initialize_passes "$WORK/llvm/InitializePasses.h"

    local OUTPUT
    if OUTPUT=$("clang-$ver" -fsyntax-only \
        -std=c++17 -fno-exceptions \
        -I"$WORK" -I"$inc" -I"$SCRIPT_DIR/include" \
        -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS \
        "$SCRIPT_DIR/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp" 2>&1); then
        pass "[LLVM $ver] no syntax errors"
    else
        fail "[LLVM $ver] syntax errors:"; echo "$OUTPUT"
    fi
    rm -rf "$WORK"
}

# ---------------------------------------------------------------------------
# Test 3: end-to-end — build .so, run on a real fuzzer via opt, check output
# Checks: no crash, correct arg names from debug info, branch sides ≠ branch line
# ---------------------------------------------------------------------------
test_e2e() {
    local ver="$1"
    local inc="/usr/lib/llvm-${ver}/include"
    info "[LLVM $ver] Test: end-to-end plugin run (opt --load-pass-plugin)"

    command -v "clang-$ver" &>/dev/null || { info "clang-$ver not found, skipping"; return; }
    command -v "opt-$ver"   &>/dev/null || { info "opt-$ver not found, skipping"; return; }

    local WORK SO BC OUTDIR
    WORK=$(mktemp -d)
    SO="$WORK/FuzzIntrospector.so"
    BC="$WORK/fuzzer.bc"
    OUTDIR="$WORK/out"
    mkdir -p "$WORK/llvm" "$OUTDIR"

    # 1. Patch a copy of InitializePasses.h
    cp "$inc/llvm/InitializePasses.h" "$WORK/llvm/"
    patch_initialize_passes "$WORK/llvm/InitializePasses.h"

    # 2. Build plugin .so — patched header shadows the system copy via first -I
    local BUILD_OUT
    if ! BUILD_OUT=$("clang-$ver" -shared -fPIC \
        -std=c++17 -fno-exceptions -funwind-tables \
        -I"$WORK" -I"$inc" -I"$SCRIPT_DIR/include" \
        -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS \
        "$SCRIPT_DIR/lib/Transforms/FuzzIntrospector/FuzzIntrospector.cpp" \
        "$SCRIPT_DIR/test_plugin_reg.cpp" \
        -o "$SO" 2>&1); then
        fail "[LLVM $ver] plugin .so build failed:"; echo "$BUILD_OUT"; rm -rf "$WORK"; return
    fi
    pass "[LLVM $ver] plugin .so built"

    # 3. Compile test fuzzer to bitcode with debug info (-O0 preserves arg names)
    if ! "clang-$ver" -c -emit-llvm -g -O0 -include stdint.h \
        "$TEST_FUZZER" -o "$BC" 2>&1; then
        fail "[LLVM $ver] fuzzer bitcode compilation failed"; rm -rf "$WORK"; return
    fi

    # 4. Run the plugin via opt
    if ! FUZZ_INTROSPECTOR=1 FUZZINTRO_OUTDIR="$OUTDIR" FI_BRANCH_PROFILE=1 \
        "opt-$ver" --load-pass-plugin="$SO" --passes="fuzz-introspector" \
        "$BC" -o /dev/null 2>&1; then
        fail "[LLVM $ver] opt crashed or failed"; rm -rf "$WORK"; return
    fi
    pass "[LLVM $ver] plugin ran without crash"

    # 5. Output YAML must exist
    local YAML
    YAML=$(ls "$OUTDIR"/*.data.yaml 2>/dev/null | head -1)
    [[ -n "$YAML" ]] || { fail "[LLVM $ver] no output YAML produced"; rm -rf "$WORK"; return; }
    pass "[LLVM $ver] output YAML produced: $(basename "$YAML")"

    # 6. Arg names must be recovered from debug info
    local ARGCHECK
    ARGCHECK=$(python3 - "$YAML" <<'PYEOF'
import yaml, sys
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
errors = []
for fn in data.get('All functions', {}).get('Elements', []):
    name = fn.get('functionName', '')
    args = fn.get('argNames', [])
    if name == 'LLVMFuzzerTestOneInput' and args != ['data', 'size']:
        errors.append(f'LLVMFuzzerTestOneInput args={args}, want [data, size]')
    if '_Z3ex4m' in name and args != ['s']:
        errors.append(f'ex4 args={args}, want [s]')
print('FAIL: ' + '; '.join(errors) if errors else 'OK')
PYEOF
)
    if [[ "$ARGCHECK" == "OK" ]]; then
        pass "[LLVM $ver] arg names correct (data/size, s)"
    else
        fail "[LLVM $ver] arg names wrong: $ARGCHECK"
    fi

    # 7. Branch sides for ex4 must differ from the branch instruction's line
    local BRCHECK
    BRCHECK=$(python3 - "$YAML" <<'PYEOF'
import yaml, sys
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
for fn in data.get('All functions', {}).get('Elements', []):
    if '_Z3ex4m' not in fn.get('functionName', ''):
        continue
    bp = fn.get('BranchProfiles', [])
    if not bp:
        print('FAIL: no BranchProfiles for ex4'); sys.exit(0)
    entry = bp[0]
    br_str = entry.get('Branch String', '')
    sides  = entry.get('Branch Sides', [])
    if len(sides) != 2:
        print(f'FAIL: expected 2 sides, got {len(sides)}'); sys.exit(0)
    br_line = br_str.split(':')[-1].split(',')[0] if ':' in br_str else ''
    for s in sides:
        loc  = s.get('BranchSide', '')
        line = loc.split(':')[-1].split(',')[0] if ':' in loc else ''
        if line and line == br_line:
            print(f'FAIL: side {loc!r} == branch line {br_str!r} (PrevLoc not filtering)')
            sys.exit(0)
    print(f'OK branch={br_str} sides={[s["BranchSide"] for s in sides]}')
PYEOF
)
    if [[ "$BRCHECK" == OK* ]]; then
        pass "[LLVM $ver] branch profiling correct: ${BRCHECK#OK }"
    else
        fail "[LLVM $ver] branch profiling: $BRCHECK"
    fi

    rm -rf "$WORK"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

# Resolve which versions to test
if [[ "$VER_ARG" == "auto" ]]; then
    VERSIONS=($(available_versions))
    if [[ ${#VERSIONS[@]} -eq 0 ]]; then
        echo "No supported LLVM (18-22) found. Install clang-XX and llvm-XX-dev."
        exit 1
    fi
    info "Auto-detected LLVM versions: ${VERSIONS[*]}"
else
    VERSIONS=("$VER_ARG")
fi

for VER in "${VERSIONS[@]}"; do
    echo ""
    echo "━━━ LLVM $VER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    case "$MODE" in
        patch)  test_patch  "$VER" ;;
        syntax) test_syntax "$VER" ;;
        e2e)    test_e2e    "$VER" ;;
        all)    test_patch  "$VER"; test_syntax "$VER"; test_e2e "$VER" ;;
        *) echo "Usage: $0 [all|patch|syntax|e2e] [18|22|auto]"; exit 1 ;;
    esac
done

echo ""
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}$FAILED test(s) FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed${NC}"
fi
