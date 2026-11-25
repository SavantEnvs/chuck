#!/usr/bin/env bash
#
# mayhem/build.sh — builds ChucK's core twice, out of tree under mayhem/build/ (gitignored):
#   fuzz/ : core + bundled libsndfile + liblo with $SANITIZER_FLAGS $DEBUG_FLAGS and SanCov,
#           linked into the four libFuzzer harnesses (+ -standalone reproducers) in /mayhem.
#   test/ : core + host (chuck_main + RtAudio with no audio API = dummy backend) with normal
#           flags -> mayhem/build/test/chuck, the CLI that mayhem/test.sh runs src/test with.
# Upstream's linux makefiles need bison/flex + ALSA/Pulse/JACK + system libsndfile; we compile the
# same object list directly instead: the pre-generated parser (core/chuck_yacc.c, which includes
# chuck.tab.h = a copy of core/chuck_yacc.h) and the bundled libsndfile (core/util_sndfile.c, as
# upstream's mac build does), with no audio backend. Re-runnable and offline (no downloads).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"
CORE="$SRC/src/core"
HOST="$SRC/src/host"
B="$SRC/mayhem/build"

CXX_CORE="chuck chuck_absyn chuck_parse chuck_errmsg chuck_frame chuck_symbol chuck_table
  chuck_vm chuck_instr chuck_scan chuck_type chuck_emit chuck_compile chuck_dl chuck_oo
  chuck_lang chuck_ugen chuck_otf chuck_stats chuck_shell chuck_io chuck_carrier chuck_globals
  hidio_sdl midiio_rtmidi rtmidi ugen_osc ugen_filter ugen_stk ugen_xxx ulib_ai ulib_doc
  ulib_machine ulib_math ulib_std ulib_opsc util_math util_buffers util_console util_hid util_platforms
  util_opsc util_serial util_string util_thread uana_xform uana_extract"
C_CORE="chuck_yacc util_network util_raw util_xforms util_sndfile"
LO="address blob bundle message method pattern_match send server server_thread timetag"

# compile_tree <outdir> <cflags...>: every core object into <outdir>/libchuck.a
compile_tree() {
  local out="$1"; shift
  local flags="$*"
  mkdir -p "$out/gen" "$out/obj/lo"
  cp "$CORE/chuck_yacc.h" "$out/gen/chuck.tab.h"
  local inc="-I$out/gen -I$CORE -I$CORE/lo -D__PLATFORM_LINUX__ -fno-strict-aliasing"
  {
    for f in $CXX_CORE; do echo "$CXX $flags $inc -c $CORE/$f.cpp -o $out/obj/$f.o"; done
    for f in $C_CORE;   do
      extra=""; [ "$f" = util_sndfile ] && extra="${SNDFILE_RELAX:-}"
      echo "$CC $flags $extra $inc -c $CORE/$f.c -o $out/obj/$f.o"; done
    for f in $LO;       do echo "$CC $flags $inc -DHAVE_CONFIG_H -c $CORE/lo/$f.c -o $out/obj/lo/$f.o"; done
  } | xargs -P "$MAYHEM_JOBS" -I{} sh -c '{} -w'
  rm -f "$out/libchuck.a"
  ar rcs "$out/libchuck.a" "$out"/obj/*.o "$out"/obj/lo/*.o
}

LIBS="-lpthread -ldl -lm"

# UBSan's `vptr` check is relaxed (only it; ASan and the rest of UBSan stay on and halting):
# tearing down any ChucK instance runs ~Chuck_Object() on Chuck_Type objects whose derived part
# is already destroyed (chuck_oo.cpp:295 `type->env()`), so `vptr` fires on EVERY input, even an
# empty one, and no target could fuzz past it.
UB_RELAX="-fno-sanitize=vptr"
# ...and `shift-base` on the bundled libsndfile only: its header logger (util_sndfile.c:4122,
# psf_log_printf's %X formatting) evaluates `0xF << 28` for every hex value it logs, which is UB
# on every ordinary .wav/.aiff, so the SndBuf target would stop on its first seed.
SNDFILE_RELAX="-fno-sanitize=shift-base"

# 1) sanitized + coverage-instrumented core for the fuzzers
rm -rf "$B/fuzz/obj"
compile_tree "$B/fuzz" $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
for h in fuzz_script fuzz_sndbuf fuzz_midifile fuzz_ai_model; do
  $CXX $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -O1 $LIB_FUZZING_ENGINE -I"$CORE" \
    "$SRC/mayhem/harnesses/$h.cpp" "$B/fuzz/lsan_off.o" "$B/fuzz/libchuck.a" $LIBS -o "$SRC/$h"
  $CXX $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -O1 -I"$CORE" \
    "$SRC/mayhem/harnesses/$h.cpp" "$B/fuzz/standalone_main.o" "$B/fuzz/lsan_off.o" "$B/fuzz/libchuck.a" $LIBS \
    -o "$SRC/$h-standalone"
done

# 2) normal-flag chuck CLI for the functional suite (mayhem/test.sh)
rm -rf "$B/test/obj"
SNDFILE_RELAX=""
compile_tree "$B/test" -O2 $COVERAGE_FLAGS
$CXX -O2 $COVERAGE_FLAGS -I"$B/test/gen" -I"$CORE" -I"$CORE/lo" -I"$HOST/RtAudio" -I"$HOST/RtAudio/include" \
  -D__PLATFORM_LINUX__ -fno-strict-aliasing \
  "$HOST/chuck_main.cpp" "$HOST/chuck_audio.cpp" "$HOST/chuck_console.cpp" "$HOST/RtAudio/RtAudio.cpp" \
  "$B/test/libchuck.a" $LIBS $COVERAGE_FLAGS -o "$B/test/chuck"
echo "build.sh: done"
