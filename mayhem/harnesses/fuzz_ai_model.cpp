// Fuzz the text model-file loaders in ulib_ai.cpp with the input as the model file.
// Input byte 0 selects the loader (mod 3): 0 = Word2Vec.load (+ getVector/getSimilar),
// 1 = MLP.load (+ predict), 2 = Wekinator.load; the remaining bytes are the file.
#include "ck_common.h"

extern "C" int LLVMFuzzerInitialize( int *, char *** ) { ck_global_setup(); return 0; }

static const char * SCRIPTS[3] = {
    "Word2Vec w;\n"
    "if( w.load( me.arg(0), -1 ) ) {\n"
    "  w.dim() => int d; if( d > 0 && d < 4096 ) {\n"
    "    float v[d]; w.getVector( \"the\", v ); string s[3]; w.getSimilar( v, 3, s ); w.getSimilar( \"the\", 3, s );\n"
    "  }\n"
    "}\n",
    "MLP m; if( m.load( me.arg(0) ) ) { float x[4]; float y[4]; m.predict( x, y ); }\n",
    "Wekinator k; k.load( me.arg(0) );\n",
};

extern "C" int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    if( size < 1 ) return -1;
    ck_run_on_file( data + 1, size - 1, "model.txt", SCRIPTS[data[0] % 3], 2 );
    return 0;
}
