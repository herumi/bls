@echo off
call ..\mcl\setvar.bat
if "%1"=="dll" (
  echo make dynamic library DLL
) else (
  echo make static library LIB
)
call setvar.bat

if "%1"=="dll" (
  cl /c %CFLAGS% /Foobj/bls_c256.obj src/bls_c256.cpp /DBLS_NO_AUTOLINK
  cl /c %CFLAGS% /Foobj/bls_c384.obj src/bls_c384.cpp /DBLS_NO_AUTOLINK
  cl /c %CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp /DBLS_NO_AUTOLINK
  cl /c %CFLAGS% /Foobj/fp.obj ../mcl/src/fp.cpp
  link /nologo /DLL /OUT:bin\bls256.dll obj\bls_c256.obj obj\fp.obj %LDFLAGS% /implib:lib\bls256.lib
  link /nologo /DLL /OUT:bin\bls384.dll obj\bls_c384.obj obj\fp.obj %LDFLAGS% /implib:lib\bls384.lib
  link /nologo /DLL /OUT:bin\bls384_256.dll obj\bls_c384_256.obj obj\fp.obj %LDFLAGS% /implib:lib\bls384_256.lib
) else (
  cl /c %CFLAGS% /Foobj/bls_c256.obj src/bls_c256.cpp
  cl /c %CFLAGS% /Foobj/bls_c384.obj src/bls_c384.cpp
  cl /c %CFLAGS% /Foobj/bls_c384_256.obj src/bls_c384_256.cpp
  cl /c %CFLAGS% /Foobj/fp.obj ../mcl/src/fp.cpp /DMCLBN_DONT_EXPORT
  lib /OUT:lib/bls256.lib /nodefaultlib obj/bls_c256.obj obj/fp.obj %LDFLAGS%
  lib /OUT:lib/bls384.lib /nodefaultlib obj/bls_c384.obj obj/fp.obj %LDFLAGS%
  lib /OUT:lib/bls384_256.lib /nodefaultlib obj/bls_c384_256.obj obj/fp.obj %LDFLAGS%
)
