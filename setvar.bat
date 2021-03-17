@echo off
call ..\mcl\setvar.bat
set BLS_CFLAGS=%CFLAGS% /I ..\mcl\include /I ./
set BLS_LDFLAGS=%LDFLAGS%
echo BLS_CFLAGS=%BLS_CFLAGS%
echo BLS_LDFLAGS=%BLS_LDFLAGS%
