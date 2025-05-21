@echo off
set MCL_DIR=./mcl
call setvar.bat
set MAKE_DLL=0
set BLS_ETH=0
set LOCAL_CFLAGS=%BLS_CFLAGS%
if "%1"=="dll" (
  set MAKE_DLL=1
  set LOCAL_CFLAGS=%BLS_CFLAGS%
  shift
) else (
  set LOCAL_CFLAGS=%BLS_CFLAGS% /DMCL_DONT_EXPORT
)
if "%1"=="eth" (
  echo make ETH mode
  set LOCAL_CFLAGS=%LOCAL_CFLAGS% -DBLS_ETH=1
  shift
)
echo LOCAL_CFLAGS=%LOCAL_CFLAGS%

ml64 -c %MCL_DIR%/src/asm/bint-x64-win.asm

set OBJS=obj\fp.obj bint-x64-win.obj

if %MAKE_DLL%==1 (
  echo make dynamic library DLL
  cl /c %LOCAL_CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp
  cl /c %LOCAL_CFLAGS% /Foobj/fp.obj %MCL_DIR%/src/fp.cpp
  link /nologo /DLL /OUT:bin\bls384_256.dll obj\bls_c384_256.obj %OBJS% %LDFLAGS% /implib:lib\bls384_256.lib
) else (
  echo make static library LIB
  cl /c %LOCAL_CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp
  cl /c %LOCAL_CFLAGS% /Foobj/fp.obj %MCL_DIR%/src/fp.cpp
  lib /OUT:lib/bls384_256.lib /nodefaultlib obj/bls_c384_256.obj %OBJS% %LDFLAGS%
)
