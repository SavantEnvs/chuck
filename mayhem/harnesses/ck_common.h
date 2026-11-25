// Shared driver for the ChucK fuzz harnesses: runs one ChucK program per input through the
// public embedding API (ChucK::init/start/compileCode/run), modelled on
// src/host-examples/example-1-minimal.cpp. A fresh ChucK instance is created and deleted per
// input. Process state an input can change, and how it is reset so each input's result depends
// only on that input:
//  - ChucK's process-global log level / system-call switch / print callbacks: re-set before
//    every input (a script calling Machine.loglevel() can't leak into the next).
//  - the random number generators: ChucK's process-global mt19937 (util_math.cpp, behind
//    Math.random*/Std.rand*/noise UGens, reseedable by Math.srandom) is reseeded with
//    ck_srandom(0), and libc's rand() (used by STK UGens and liblo) with srand(1), right after
//    every instance's init() (which itself calls ck_randomize()), so random values depend only
//    on the input's own draws/seeds. (Math.randomize() is
//    nondeterministic by contract: it seeds from std::random_device.)
//  - Machine.crash(): ChucK's documented "explicitly crash the virtual machine" builtin
//    (ulib_machine.cpp machine_crash_impl writes to address 0 on purpose). After every init()
//    its native implementation in the new instance's type system is swapped for a no-op
//    (ck_disarm_crash), so no input -- including one that builds the call at run time through
//    Machine.eval -- reaches the deliberate crash, and no input is filtered for it.
//  - the process environment (Std.setenv, ulib_std.cpp): snapshot taken once at setup (with
//    HOME and TMPDIR pointed at the scratch dir), restored with clearenv() after every input.
//  - files: a script's relative paths resolve against the per-process scratch dir
//    (CHUCK_PARAM_WORKING_DIRECTORY), which is emptied after every input. While an input runs,
//    every libc open for writing (fopen/fopen64/open/open64/creat/creat64 -- what FileIO's
//    fstream, WvOut's bundled libsndfile and util_platforms' temp files go through) of a path
//    outside the scratch dir is redirected into it (see ck_map_path), and reads of such a path
//    see the redirected copy if the same input wrote one. So nothing an input writes survives it.
//    Only libFuzzer's own writes (corpus/artifacts, outside ck_run) are left alone.
#pragma once
#include "chuck.h"
#include "chuck_compile.h"
#include "chuck_type.h"
#include "util_math.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <ftw.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <vector>

extern char ** environ;

static char g_scratch[4096];
static size_t g_scratch_len = 0;
static volatile bool g_in_input = false;             // true only while ck_run executes an input
static std::vector<std::pair<std::string, std::string> > g_env;  // environment snapshot

// ---- file sandbox: interpose libc's opening functions (mocks the environment, not target code) ----
// a path is contained iff it lies under the scratch dir and has no ".." component
static bool ck_contained( const char * p )
{
    if( strncmp( p, g_scratch, g_scratch_len ) != 0 || p[g_scratch_len] != '/' ) return false;
    for( const char * q = p + g_scratch_len; ( q = strstr( q, ".." ) ); q += 2 )
        if( q[-1] == '/' && ( q[2] == '/' || q[2] == 0 ) ) return false;
    return true;
}

// flatten an uncontained path into one file in the scratch dir: "/tmp/x" -> <scratch>/abs__tmp_x
static const char * ck_map_path( const char * p, char * buf, size_t n )
{
    if( !g_in_input || !p || !g_scratch_len || ck_contained( p ) ) return p;
    size_t o = (size_t)snprintf( buf, n, "%s/abs_", g_scratch );
    for( ; *p && o + 1 < n; p++ ) buf[o++] = ( *p == '/' ) ? '_' : *p;
    buf[o] = 0;
    return buf;
}

// writes are always redirected; reads only when this input already wrote the redirected copy
static const char * ck_map_open( const char * p, bool writing, char * buf, size_t n )
{
    const char * m = ck_map_path( p, buf, n );
    if( m == p || writing ) return m;
    struct stat st;
    return stat( m, &st ) == 0 ? m : p;
}

static bool ck_mode_writes( const char * mode ) { return mode && strpbrk( mode, "wa+" ); }
static bool ck_flags_write( int flags ) { return ( flags & ( O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND ) ) != 0; }

#define CK_REAL( ret, name, ... ) \
    static ret (*real)( __VA_ARGS__ ) = 0; \
    if( !real ) real = (ret (*)( __VA_ARGS__ ))dlsym( RTLD_NEXT, name );

extern "C" FILE * fopen( const char * p, const char * mode )
{
    CK_REAL( FILE *, "fopen", const char *, const char * )
    char b[8192]; return real( ck_map_open( p, ck_mode_writes( mode ), b, sizeof(b) ), mode );
}
extern "C" FILE * fopen64( const char * p, const char * mode )
{
    CK_REAL( FILE *, "fopen64", const char *, const char * )
    char b[8192]; return real( ck_map_open( p, ck_mode_writes( mode ), b, sizeof(b) ), mode );
}
extern "C" int open( const char * p, int flags, ... )
{
    CK_REAL( int, "open", const char *, int, ... )
    va_list ap; va_start( ap, flags ); mode_t m = (mode_t)va_arg( ap, int ); va_end( ap );
    char b[8192]; return real( ck_map_open( p, ck_flags_write( flags ), b, sizeof(b) ), flags, m );
}
extern "C" int open64( const char * p, int flags, ... )
{
    CK_REAL( int, "open64", const char *, int, ... )
    va_list ap; va_start( ap, flags ); mode_t m = (mode_t)va_arg( ap, int ); va_end( ap );
    char b[8192]; return real( ck_map_open( p, ck_flags_write( flags ), b, sizeof(b) ), flags, m );
}
extern "C" int creat( const char * p, mode_t m )
{
    CK_REAL( int, "creat", const char *, mode_t )
    char b[8192]; return real( ck_map_open( p, true, b, sizeof(b) ), m );
}
extern "C" int creat64( const char * p, mode_t m )
{
    CK_REAL( int, "creat64", const char *, mode_t )
    char b[8192]; return real( ck_map_open( p, true, b, sizeof(b) ), m );
}

// ---- environment snapshot / restore ----
static void ck_env_snapshot()
{
    g_env.clear();
    for( char ** e = environ; e && *e; e++ )
    {
        const char * eq = strchr( *e, '=' );
        if( eq ) g_env.push_back( std::make_pair( std::string( *e, eq - *e ), std::string( eq + 1 ) ) );
    }
}

static void ck_env_restore()
{
    clearenv();
    for( size_t i = 0; i < g_env.size(); i++ )
        setenv( g_env[i].first.c_str(), g_env[i].second.c_str(), 1 );
}

static void ck_quiet( const char * ) {}

static int ck_rm_entry( const char * path, const struct stat *, int, struct FTW * ftw )
{
    if( ftw->level > 0 ) remove( path );
    return 0;
}

// empty the scratch dir (files a script wrote with FileIO/WvOut, or our own input file)
static void ck_clean_scratch()
{
    nftw( g_scratch, ck_rm_entry, 16, FTW_DEPTH | FTW_PHYS );
}

static void ck_global_setup()
{
    const char * tmp = getenv( "TMPDIR" );
    if( !tmp || !*tmp ) tmp = "/tmp";
    snprintf( g_scratch, sizeof(g_scratch), "%s/chuckfuzz.XXXXXX", tmp );
    if( !mkdtemp( g_scratch ) ) { perror( "mkdtemp" ); abort(); }
    g_scratch_len = strlen( g_scratch );
    // anything that looks for a home or temp dir lands in the scratch dir too
    setenv( "HOME", g_scratch, 1 );
    setenv( "TMPDIR", g_scratch, 1 );
    ck_env_snapshot();
    // (no chdir: libFuzzer resolves corpus/artifact paths against the cwd; ChucK resolves a
    // script's relative paths against CHUCK_PARAM_WORKING_DIRECTORY = the scratch dir)
}

// ChucK's deliberate-crash builtin (ulib_machine.cpp) and its replacement
CK_DLL_SFUN( machine_crash_impl );
CK_DLL_SFUN( ck_crash_noop ) { }

// point Machine.crash() of this instance at ck_crash_noop (matched by its native function, so
// only the deliberate-crash builtin is affected)
static void ck_disarm_crash( ChucK * ck )
{
    Chuck_Env * env = ck->compiler()->env();
    Chuck_Type * machine = env ? env->global()->lookup_type( std::string( "Machine" ) ) : NULL;
    if( !machine || !machine->nspc ) { fprintf( stderr, "ck_common: no Machine type\n" ); abort(); }
    std::vector<Chuck_Func *> funcs;
    machine->nspc->get_funcs( funcs );
    int n = 0;
    for( size_t i = 0; i < funcs.size(); i++ )
    {
        Chuck_VM_Code * code = funcs[i]->code;
        if( code && code->native_func == (t_CKUINT)machine_crash_impl )
        { code->native_func = (t_CKUINT)ck_crash_noop; n++; }
    }
    if( n == 0 ) { fprintf( stderr, "ck_common: Machine.crash not found\n" ); abort(); }
}

// run `code` with ':'-separated `args` (me.arg(i)) for at most `max_buffers` buffers of audio
static void ck_run( const std::string & code, const std::string & args, int max_buffers )
{
    const int frames = 256;
    static SAMPLE in[frames * 2], out[frames * 2];

    g_in_input = true;
    ChucK::setLogLevel( CK_LOG_NONE );
    ChucK::enableSystemCall = FALSE;   // keep Std.system() disabled (upstream default)
    ChucK::setStdoutCallback( ck_quiet );
    ChucK::setStderrCallback( ck_quiet );

    ChucK * ck = new ChucK();
    ck->setParam( CHUCK_PARAM_SAMPLE_RATE, 44100 );
    ck->setParam( CHUCK_PARAM_INPUT_CHANNELS, 2 );
    ck->setParam( CHUCK_PARAM_OUTPUT_CHANNELS, 2 );
    ck->setParam( CHUCK_PARAM_VM_HALT, TRUE );
    ck->setParam( CHUCK_PARAM_IS_REALTIME_AUDIO_HINT, FALSE );
    ck->setParam( CHUCK_PARAM_CHUGIN_ENABLE, FALSE );   // never dlopen .chug files
    ck->setParam( CHUCK_PARAM_OTF_ENABLE, FALSE );      // no network listener
    ck->setParam( CHUCK_PARAM_WORKING_DIRECTORY, std::string( g_scratch ) );
    ck->init();
    // reseed AFTER init(): loading the Math library (ulib_math.cpp libmath_query) calls
    // ck_randomize(), which reseeds the global RNG from std::random_device
    ck_srandom( 0 );   // ChucK's global RNG (Math.random*, Std.rand*, Math.srandom)
    srand( 1 );        // libc rand() (STK UGens, liblo); 1 = glibc's initial seed
    ck_disarm_crash( ck );
    ck->setChoutCallback( ck_quiet );
    ck->setCherrCallback( ck_quiet );
    ck->start();

    if( ck->compileCode( code, args, 1 ) )
    {
        memset( in, 0, sizeof(in) );
        for( int i = 0; i < max_buffers && ck->vm_running(); i++ )
            ck->run( in, out, frames );
    }
    delete ck;
    g_in_input = false;
    ck_clean_scratch();
    ck_env_restore();
}

// write the fuzz input to a file in the scratch dir and run a fixed script on it (me.arg(0))
static void ck_run_on_file( const uint8_t * data, size_t size, const char * name,
                            const char * script, int max_buffers )
{
    std::string path = std::string( g_scratch ) + "/" + name;
    FILE * f = fopen( path.c_str(), "wb" );
    if( !f ) { perror( "fopen" ); abort(); }
    if( size ) fwrite( data, 1, size, f );
    fclose( f );
    ck_run( script, path, max_buffers );
}
