rem @echo off

call setvar.bat dll
echo make bls384.dll
cl /c %CFLAGS% /DBLS_NO_AUTOLINK /Foobj/bls_c.obj src/bls_c.cpp
cl /c %CFLAGS% /DBLS_NO_AUTOLINK /Foobj/fp.obj ../mcl/src/fp.cpp
lib /OUT:lib/bls384.lib /nodefaultlib obj/bls_c.obj obj/fp.obj %LDFLAGS%
cl /LD /MT obj/bls_c.obj obj/fp.obj %CFLAGS% /link /out:bin/bls384.dll %LDFLAGS%
