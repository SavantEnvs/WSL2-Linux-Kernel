#!/usr/bin/env bash
#
# mayhem/test.sh — runs the oracle binaries that mayhem/build.sh built with the project's normal flags:
#   * tools/bootconfig/bootconfig (upstream's userspace build of lib/bootconfig.c) driven by upstream's own
#     tools/bootconfig/test-bootconfig.sh, plus golden-output checks on the parsed tree;
#   * mayhem/kat/fdt_kat: known answers from the kernel's libfdt (scripts/dtc/libfdt);
#   * mayhem/kat/bpf_kat: known answers from the kernel's libbpf (tools/lib/bpf) on a clang-built BPF object.
# Every verdict is a bash-side comparison of the program's output against a recorded value.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build/test"
for f in bootconfig fdt_kat bpf_kat kat_prog.bpf.o kat_prog.btf; do
  [ -e "$T/$f" ] || { echo "test.sh: $T/$f missing (mayhem/build.sh should have built it)" >&2; emit_ctrf kernel-userspace-kat 0 1; exit 1; }
done

pass=0; fail=0
check() { # check <name> <expected> <actual>
  if [[ "$3" == "$2" ]]; then pass=$((pass + 1)); else
    fail=$((fail + 1)); echo "FAIL: $1" >&2; printf '  expected: %q\n  actual:   %q\n' "$2" "$3" >&2
  fi
}
contains() { # contains <name> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then pass=$((pass + 1)); else
    fail=$((fail + 1)); echo "FAIL: $1 (missing: $2)" >&2
  fi
}

# --- upstream's own bootconfig test script ------------------------------------------------------------
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
cp "$T/bootconfig" "$scratch/bootconfig"
out="$(cd "$SRC/tools/bootconfig" && sh ./test-bootconfig.sh "$scratch" 2>&1)"
npass="$(sed -n 's/^# of Passed: //p' <<<"$out")"
nfail="$(sed -n 's/^# of Failed: //p' <<<"$out")"
if [[ "$npass" =~ ^[0-9]+$ && "$nfail" =~ ^[0-9]+$ && "$npass" -ge 55 ]]; then
  pass=$((pass + npass)); fail=$((fail + nfail))
  [ "$nfail" -eq 0 ] || { echo "$out" | grep -B1 '\[NG\]' >&2; }
else
  fail=$((fail + 1)); echo "FAIL: test-bootconfig.sh gave no usable summary" >&2; echo "$out" | tail -20 >&2
fi

# --- bootconfig: parsed-tree golden output --------------------------------------------------------------
BC="$T/bootconfig"
S="$SRC/tools/bootconfig/samples"
check "bootconfig good-tree" 'key {
	word.tree.value = "0";
	word2.tree.value = "1", "2";
}
other.tree {
	value = "2";
	value2 = "3";
}' "$("$BC" "$S/good-tree.bconf" 2>&1)"
check "bootconfig good-mixed-override" 'key = "value2";
key.foo = "bar";' "$("$BC" "$S/good-mixed-override.bconf" 2>&1)"
check "bootconfig -l flat keys" 'key.word.tree.value = "0"
key.word2.tree.value = "1", "2"
other.tree.value = "2"
other.tree.value2 = "3"' "$("$BC" -l "$S/good-tree.bconf" 2>&1)"
check "bootconfig good-simple" 'key {
	word1 = "1";
	word2 = "2";
	word3 = "3";
	word4 = "4";
	word5 = "5";
	word6 = "6";
}' "$("$BC" "$S/good-simple.bconf" 2>&1)"
check "bootconfig good-array-space-comment" 'key = "value1", "value2", "value3";' "$("$BC" "$S/good-array-space-comment.bconf" 2>&1)"
check "bootconfig bad-tree error" 'Parse Error: Brace is not closed at 2:1' "$("$BC" "$S/bad-tree.bconf" 2>&1)"
contains "bootconfig bad-no-keyword is a parse error" "Parse Error" "$("$BC" "$S/bad-no-keyword.bconf" 2>&1)"

# --- libfdt known answers -------------------------------------------------------------------------------
check "libfdt kat" 'magic=0xd00dfeed version=17
model=Mayhem KAT len=11
soc compat count=2
soc matches vendor,bus=0 vendor,none=1
phandle 7 -> /soc/serial@1000
serial reg=0x1000,0x100 len=8
bad path -> FDT_ERR_NOTFOUND
after edit: serial=FDT_ERR_NOTFOUND soc children=0
bad header check=FDT_ERR_BADMAGIC' "$("$T/fdt_kat" 2>&1)"

# --- libbpf known answers -------------------------------------------------------------------------------
check "libbpf kat" 'prog kat_sock sec=socket type=1
prog kat_xdp sec=xdp type=6
map kat_map type=1 key=4 value=16 max=16
kat_value struct found=yes size=16
typedef unsigned int __u32;

typedef unsigned long long __u64;

struct kat_value {
	__u32 a;
	__u64 b;
};

built btf: int=1 struct=2 size=8
struct point {
	unsigned int x;
	unsigned int y;
};' "$("$T/bpf_kat" "$T/kat_prog.bpf.o" "$T/kat_prog.btf" 2>&1)"

emit_ctrf kernel-userspace-kat "$pass" "$fail"
