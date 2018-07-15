@echo off

call setvar.bat lib
echo make lib/lib384.%MODE%
echo CFLAGS=%CFLAGS%
cl /c %CFLAGS% /Foobj/bls_c.obj src/bls_c.cpp
cl /c %CFLAGS% /Foobj/fp.obj ../mcl/src/fp.cpp
lib /OUT:lib/bls384.lib /nodefaultlib obj/bls_c.obj obj/fp.obj %LDFLAGS%
