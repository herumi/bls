@echo off
set MCL_DIR=./mcl
call setvar.bat
set MAKE_DLL=0
set BLS_ETH=0
set LOCAL_CFLAGS=%BLS_CFLAGS%
if "%1"=="dll" (
  set MAKE_DLL=1
  set LOCAL_CFLAGS=%BLS_CFLAGS% /DMCLBN_DLL_EXPORT /DMCL_DLL_EXPORT /DMCLBN_FORCE_EXPORT
  shift
)
if "%1"=="eth" (
  echo make ETH mode
  set LOCAL_CFLAGS=%LOCAL_CFLAGS% -DBLS_ETH=1
  shift
)
echo LOCAL_CFLAGS=%LOCAL_CFLAGS%

set LOCAL_CFLAGS=%LOCAL_CFLAGS% /DMCL_NO_AUTOLINK
ml64 -c %MCL_DIR%/src/asm/bint-x64-win.asm

set OBJS=obj\fp.obj bint-x64-win.obj

if %MAKE_DLL%==1 (
  echo make dynamic library DLL
  cl /c %LOCAL_CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp /DBLS_NO_AUTOLINK
  cl /c %LOCAL_CFLAGS% /Foobj/fp.obj %MCL_DIR%/src/fp.cpp
  link /nologo /DLL /OUT:bin\bls384_256.dll obj\bls_c384_256.obj %OBJS% %LDFLAGS% /implib:lib\bls384_256.lib
) else (
  echo make static library LIB
  cl /c %LOCAL_CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp
  cl /c %LOCAL_CFLAGS% /Foobj/fp.obj %MCL_DIR%/src/fp.cpp /DMCLBN_DONT_EXPORT /DMCLBN_FORCE_EXPORT
  lib /OUT:lib/bls384_256.lib /nodefaultlib obj/bls_c384_256.obj %OBJS% %LDFLAGS%
)
