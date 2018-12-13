@echo off
call ..\mcl\setvar.bat
set CFLAGS=%CFLAGS% /I ..\mcl\include /I ./
set LDFLAGS=%LDFLAGS% /LIBPATH:..\mcl\lib
echo CFLAGS=%CFLAGS%
echo LDFLAGS=%LDFLAGS%
