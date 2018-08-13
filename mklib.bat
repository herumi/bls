@echo off
call ..\mcl\setvar.bat
if "%1"=="dll" (
  echo make dynamic library DLL
) else (
  echo make static library LIB
)
call setvar.bat

if "%1"=="dll" (
  cl /c %CFLAGS% /Foobj/bls_c.obj src/bls_c.cpp /DBLS_NO_AUTOLINK
  cl /c %CFLAGS% /Foobj/fp.obj ../mcl/src/fp.cpp
  link /nologo /DLL /OUT:bin\bls384.dll obj\bls_c.obj obj\fp.obj %LDFLAGS% /implib:lib\bls384.lib
) else (
  cl /c %CFLAGS% /Foobj/bls_c.obj src/bls_c.cpp
  cl /c %CFLAGS% /Foobj/fp.obj ../mcl/src/fp.cpp /DMCLBN_DONT_EXPORT
  lib /OUT:lib/bls384.lib /nodefaultlib obj/bls_c.obj obj/fp.obj %LDFLAGS%
  cl /c %CFLAGS% /Foobj/bls.obj src/bls.cpp
  lib /OUT:lib/bls.lib /nodefaultlib obj/bls.obj obj/fp.obj %LDFLAGS%
)
