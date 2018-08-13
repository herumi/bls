@echo off
call ..\mcl\setvar.bat
set MCLBN_FP_UNIT_SIZE=6
set CFLAGS=%CFLAGS% /DMCLBN_FP_UNIT_SIZE=%MCLBN_FP_UNIT_SIZE% /I ..\mcl\include
set LDFLAGS=%LDFLAGS% /LIBPATH:..\mcl\lib
echo CFLAGS=%CFLAGS%
echo LDFLAGS=%LDFLAGS%