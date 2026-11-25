// Fuzz the Standard MIDI File parser behind MidiFileIn.open()/read() (stk::MidiFileIn) with the
// input as the .mid file.
#include "ck_common.h"

extern "C" int LLVMFuzzerInitialize( int *, char *** ) { ck_global_setup(); return 0; }

static const char * SCRIPT =
    "MidiFileIn m; MidiMsg g;\n"
    "if( m.open( me.arg(0) ) ) {\n"
    "  for( 0 => int t; t < m.numTracks(); t++ ) {\n"
    "    0 => int n;\n"
    "    while( n < 10000 && m.read( g, t ) ) { n++; }\n"
    "  }\n"
    "  m.rewind();\n"
    "  0 => int k; while( k < 10000 && m.read( g ) ) { k++; }\n"
    "  m.close();\n"
    "}\n";

extern "C" int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    ck_run_on_file( data, size, "input.mid", SCRIPT, 2 );
    return 0;
}
