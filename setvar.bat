@echo off
set MCLBN_FP_UNIT_SIZE=4
echo MCLBN_FP_UNIT_SIZE=%MCLBN_FP_UNIT_SIZE%
set CFLAGS=/MT /DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc /nologo -I ./include -I../cybozulib/include -I../cybozulib_ext/include -I../mcl/include/
set CFLAGS=%CFLAGS% /DMCLBN_FP_UNIT_SIZE=%MCLBN_FP_UNIT_SIZE% /DMCL_NO_AUTOLINK
set LDFLAGS=/LIBPATH:..\cybozulib_ext\lib /LIBPATH:.\lib /LIBPATH:..\mcl\lib
