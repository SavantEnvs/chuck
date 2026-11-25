// Fuzz the audio-file readers behind SndBuf.read() (ChucK's bundled libsndfile, util_sndfile.c,
// plus SndBuf's sample access/interpolation) with the input as the audio file.
// The script sets `0 => b.chunks` (load the whole file at once): in SndBuf's default chunked mode
// sndbuf_load computes `d->buffer + d->num_samples` with d->buffer == NULL (ugen_xxx.cpp:4007),
// which UBSan's pointer-overflow check reports on every audio file, valid or not.
#include "ck_common.h"

extern "C" int LLVMFuzzerInitialize( int *, char *** ) { ck_global_setup(); return 0; }

static const char * SCRIPT =
    "SndBuf b => blackhole;\n"
    "0 => b.chunks;\n"
    "me.arg(0) => b.read;\n"
    "b.samples() => int n;\n"
    "b.channels(); b.length();\n"
    "if( n > 0 ) { (n/2) => b.pos; 1 => b.loop; -1.0 => b.rate; }\n"
    "256::samp => now;\n"
    "2.0 => b.rate; 0 => b.pos;\n"
    "256::samp => now;\n";

extern "C" int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    ck_run_on_file( data, size, "input.wav", SCRIPT, 4 );
    return 0;
}
