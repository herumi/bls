@echo off
set BLS_MAX_OP_UNIT_SIZE=4
echo BLS_MAX_OP_UNIT_SIZE=%BLS_MAX_OP_UNIT_SIZE%
set CFLAGS=/MT /DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc /nologo -I ./include -I../cybozulib/include -I../cybozulib_ext/include -I../mcl/include
set CFLAGS=%CFLAGS% -DBLS_MAX_OP_UNIT_SIZE=%BLS_MAX_OP_UNIT_SIZE%
set LDFLAGS=/LIBPATH:..\cybozulib_ext\lib /LIBPATH:.\lib /LIBPATH:..\mcl\lib
