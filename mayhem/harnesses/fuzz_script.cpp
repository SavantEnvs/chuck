// Fuzz the ChucK language end to end: lexer/parser, type checker (incl. control-path analysis),
// emitter and VM, by compiling and running the input as ChucK source via ChucK::compileCode.
#include "ck_common.h"

extern "C" int LLVMFuzzerInitialize( int *, char *** ) { ck_global_setup(); return 0; }

extern "C" int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    std::string code( (const char *)data, size );
    // (Machine.crash(), the deliberate-crash builtin, is disarmed in ck_run: ck_disarm_crash)
    // 8 buffers (~46 ms of audio): enough for compile, type-check, emit and the first shreds to
    // run; each ChucK instance's init() (~40 ms under ASan) already dominates the exec time
    ck_run( code, "", 8 );
    return 0;
}
