@echo off
set MCL_DIR=mcl
pushd %MCL_DIR%
if "%1" == "dll" (
	call mklib.bat dll
) else (
	call mklib.bat
)
popd
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

set OBJS=%MCL_DIR%\obj\fp.obj %MCL_DIR%\obj\msm_avx.obj %MCL_DIR%\bint-x64-win.obj
set OBJS=%OBJS% obj\bls_c384_256.obj

cl /c %LOCAL_CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp

echo lib /nologo /OUT:lib/bls384_256.lib /nodefaultlib %OBJS%
lib /nologo /OUT:lib/bls384_256.lib /nodefaultlib %OBJS%

if "%MAKE_DLL%" == "1" (
  echo make dynamic library DLL
  echo link /nologo /DLL /OUT:bin\bls384_256.dll %OBJS% %LDFLAGS% /implib:lib\bls384_256.lib
  link /nologo /DLL /OUT:bin\bls384_256.dll %OBJS% %LDFLAGS% /implib:lib\bls384_256.lib
) else (
  echo make static library LIB
)
