#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses for the kernel code that builds as ordinary userspace
# code from this tree: lib/bootconfig.c (the way tools/bootconfig does), scripts/dtc/libfdt, and
# tools/lib/bpf (libbpf). Also builds the normal-flags oracle binaries that mayhem/test.sh runs.
#
# Re-runnable and air-gapped: everything resolves from the tree and from apt packages baked into the
# image (libelf-dev, zlib1g-dev); nothing is fetched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
B="$SRC/mayhem/build"
H="$SRC/mayhem/harnesses"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test" "$B/seeds"

# SanCov on the library code (fuzzer-no-link) so the fuzzed kernel code carries coverage, plus the
# sanitizers and DWARF<=3. $SANITIZER_FLAGS may be empty (no-sanitizer build); coverage stays.
FZ="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

# The kernel's own userspace headers (tools/include) and libbpf's include dir.
KINC="-I$SRC/tools/include -I$SRC/tools/include/uapi -I$SRC/tools/arch/x86/include"
BPF_INC="$KINC -I$SRC/tools/lib/bpf"
BPF_DEFS="-D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
BPF_SRCS="libbpf bpf nlattr btf libbpf_utils netlink bpf_prog_linfo libbpf_probes hashmap btf_dump
          ringbuf strset linker gen_loader relo_core usdt zip elf features btf_iter btf_relocate"
BPF_LIBS="-lelf -lz"

# Compile in parallel; each job writes its own object.
compile_all() { # compile_all <outdir> <cflags> <src>...
  local out="$1" flags="$2"; shift 2
  printf '%s\n' "$@" | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
    "$CC $flags -c {} -o $out/\$(basename {} .c).o"
}

# --- lsan hook (leak detection is off by build, never by runtime option) -----------------------------
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"

# link_pair <name> <extra objs/libs...>: fuzzer binary + standalone reproducer.
link_pair() {
  local name="$1"; shift
  $CC $FZ $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$@" -o "$SRC/$name"
  $CC $FZ "$B/fuzz/standalone_main.o" "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$@" -o "$SRC/$name-standalone"
}

# --- 1) bootconfig: lib/bootconfig.c via the tools/bootconfig userspace shim --------------------------
BC_INC="-I$SRC/tools/bootconfig/include"
$CC $FZ $BC_INC -c "$SRC/lib/bootconfig.c" -o "$B/fuzz/bootconfig_lib.o"
$CC $FZ $BC_INC -c "$H/fuzz_bootconfig.c" -o "$B/fuzz/fuzz_bootconfig.o"
link_pair fuzz_bootconfig "$B/fuzz/bootconfig_lib.o"

# --- 2) libfdt ----------------------------------------------------------------------------------------
FDT_INC="-I$SRC/scripts/dtc/libfdt"
mkdir -p "$B/fuzz/fdt"
compile_all "$B/fuzz/fdt" "$FZ $FDT_INC" "$SRC"/scripts/dtc/libfdt/fdt*.c
$CC $FZ $FDT_INC -c "$H/fuzz_fdt.c" -o "$B/fuzz/fuzz_fdt.o"
link_pair fuzz_fdt "$B"/fuzz/fdt/*.o

# --- 3) libbpf: object loader and BTF -----------------------------------------------------------------
mkdir -p "$B/fuzz/bpf"
bpf_files=()
for f in $BPF_SRCS; do bpf_files+=("$SRC/tools/lib/bpf/$f.c"); done
compile_all "$B/fuzz/bpf" "$FZ $BPF_INC $BPF_DEFS" "${bpf_files[@]}"
for t in fuzz_libbpf_object fuzz_libbpf_btf; do
  $CC $FZ $BPF_INC $BPF_DEFS -c "$H/$t.c" -o "$B/fuzz/$t.o"
  link_pair "$t" "$B"/fuzz/bpf/*.o $BPF_LIBS
done

# --- oracle binaries, normal flags (no sanitizer, no SanCov, no -gdwarf-3) ---------------------------
$CC -O2 $COVERAGE_FLAGS -Wall $BC_INC "$SRC/tools/bootconfig/main.c" "$SRC/lib/bootconfig.c" \
    -o "$B/test/bootconfig"
$CC -O2 $COVERAGE_FLAGS $FDT_INC "$SRC/mayhem/kat/fdt_kat.c" "$SRC"/scripts/dtc/libfdt/fdt*.c \
    -o "$B/test/fdt_kat"
$CC -O2 $COVERAGE_FLAGS $BPF_INC $BPF_DEFS "$SRC/mayhem/kat/bpf_kat.c" "${bpf_files[@]}" $BPF_LIBS \
    -o "$B/test/bpf_kat"

# BPF fixture compiled from source with the image's clang: an object with programs, a map, BTF.
"$CC" -target bpf -O2 -g -nostdinc -I"$SRC/mayhem/kat/bpf-include" -I"$SRC/include/uapi" -I"$SRC/arch/x86/include/uapi" \
    -c "$SRC/mayhem/kat/kat_prog.bpf.c" -o "$B/test/kat_prog.bpf.o"
llvm-objcopy --dump-section=.BTF="$B/test/kat_prog.btf" "$B/test/kat_prog.bpf.o" "$B/test/kat_prog.stripped.o"
echo "build.sh: done"
