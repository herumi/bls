@echo off
set MODE=
if /i "%1"=="lib" (
  set MODE=lib
)
if /i "%1"=="dll" (
  set MODE=dll
)
if "%MODE%"=="" (
  echo error
  echo setvar lib or dll
  goto exit
)
set MCLBN_FP_UNIT_SIZE=6
set CFLAGS=/MT /DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc /nologo
set CFLAGS=%CFLAGS% -I ./include -I../cybozulib/include -I../cybozulib_ext/include -I../mcl/include/ -I../mcl/src -I./ -I../xbyak/
set CFLAGS=%CFLAGS% /DMCLBN_FP_UNIT_SIZE=%MCLBN_FP_UNIT_SIZE% /DMCL_NO_AUTOLINK /DMCLBN_NO_AUTOLINK
set LDFLAGS=/LIBPATH:../cybozulib_ext/lib /LIBPATH:./lib

if %MODE%==lib (
  set CFLAGS=%CFLAGS% /DBLS_DONT_EXPORT
)

:exit
