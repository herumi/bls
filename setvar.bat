set CFLAGS=/MT /DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc /nologo -I ./include -I../cybozulib/include -I../cybozulib_ext/include -I../mcl/include
set CFLAGS=%CFLAGS% -DBLS_MAX_OP_UNIT_SIZE=6
set LDFLAGS=/LIBPATH:..\cybozulib_ext\lib /LIBPATH:.\lib /LIBPATH:..\mcl\lib
