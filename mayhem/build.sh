#!/usr/bin/env bash
#
# mayhem/build.sh — packetdrill fuzz targets + the upstream unit tests.
#
#  1) Oracle build: upstream's own Makefile, in tree, normal flags (objects are gitignored by
#     upstream): packetdrill, checksum_test, packet_parser_test, packet_to_string_test.
#  2) Fuzz build: every packetdrill-lib object (the list is read from upstream's Makefile.common)
#     compiled out of tree into mayhem/build/fuzz with $SANITIZER_FLAGS $DEBUG_FLAGS, then
#       - mayhem/build/fuzz/packetdrill            the CLI (raw target: packetdrill --dry_run @@)
#       - mayhem/build/fuzz/fuzz_packet_parser     libFuzzer harness (+ -standalone reproducer)
#     Re-runnable and offline: everything is rebuilt from the tree with bison/flex/clang from the image.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
# UBSan relaxations, two checks only (ASan and the rest of UBSan stay on and halting):
#  - shift-base: netmask_to_prefix() (ip_address.c) evaluates `1<<pos` with pos=31 on a signed
#    int while finalizing the DEFAULT config, so every script aborted before parsing.
#  - alignment: TCP options are byte-packed on the wire; parser.y and the option code access
#    `struct sack_block`/u32 fields in them in place (x86-benign), so every script with a SACK
#    option aborted.
[ -z "$SANITIZER_FLAGS" ] || SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=shift-base,alignment"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

PD="$SRC/gtests/net/packetdrill"
OUT="$SRC/mayhem/build/fuzz"
LIBS="-lpthread -lrt -ldl"

# 1) Oracle build (upstream Makefile, normal flags).
make -C "$PD" -j"$MAYHEM_JOBS" CC="$CC" packetdrill-extra-cflags="$COVERAGE_FLAGS" \
  packetdrill-ext-libs="$LIBS $COVERAGE_FLAGS" \
  packetdrill checksum_test packet_parser_test packet_to_string_test

# 2) Fuzz builds, out of tree. Two object sets from the same sources:
#    raw/ — ASan+UBSan only, for the CLI that Mayhem runs as an uninstrumented file-input target;
#    lf/  — plus SanCov (-fsanitize=fuzzer-no-link), linked into the libFuzzer harness.
LIB_OBJS=$(make -s -C "$PD" -f Makefile.common --no-print-directory \
  --eval 'mayhem-print-lib: ; @echo $(packetdrill-lib)' mayhem-print-lib)
GEN="$OUT/gen"
mkdir -p "$GEN" "$OUT/raw" "$OUT/lf"
( cd "$PD" && bison --output="$GEN/parser.c" --defines="$GEN/parser.h" parser.y \
  && flex -o"$GEN/lexer.c" lexer.l )

BASE_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -I$GEN -I$PD"
jobs_list=()
for o in $LIB_OBJS packetdrill.o; do
  base="${o%.o}"
  case "$base" in
    parser|lexer) src="$GEN/$base.c" ;;
    *) src="$PD/$base.c" ;;
  esac
  [ -f "$src" ] || { echo "missing source for $o: $src" >&2; exit 1; }
  jobs_list+=("$src raw/$o" "$src lf/$o")
done
jobs_list+=("$SRC/mayhem/harnesses/fuzz_packet_parser.c lf/fuzz_packet_parser.o")
export CC BASE_CFLAGS OUT
printf '%s\n' "${jobs_list[@]}" | xargs -P "$MAYHEM_JOBS" -L1 bash -c '
  set -e; extra=""; case "$1" in lf/*) extra="-fsanitize=fuzzer-no-link" ;; esac
  $CC $BASE_CFLAGS $extra -c "$0" -o "$OUT/$1"'

raw_objs=(); lf_objs=()
for o in $LIB_OBJS; do raw_objs+=("$OUT/raw/$o"); lf_objs+=("$OUT/lf/$o"); done

"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# The CLI (raw file-input target `packetdrill --dry_run @@`): upstream's main() and objects.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -o "$OUT/packetdrill" \
  "$OUT/raw/packetdrill.o" "${raw_objs[@]}" "$OUT/lsan_off.o" $LIBS
# libFuzzer harness + its run-once reproducer.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -o "$OUT/fuzz_packet_parser" \
  "$OUT/lf/fuzz_packet_parser.o" "${lf_objs[@]}" "$OUT/lsan_off.o" $LIBS
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -o "$OUT/fuzz_packet_parser-standalone" \
  "$OUT/standalone_main.o" "$OUT/lf/fuzz_packet_parser.o" "${lf_objs[@]}" "$OUT/lsan_off.o" $LIBS

ls -la "$OUT/packetdrill" "$OUT/fuzz_packet_parser" "$OUT/fuzz_packet_parser-standalone" \
  "$PD/packetdrill" "$PD/checksum_test" "$PD/packet_parser_test" "$PD/packet_to_string_test"
