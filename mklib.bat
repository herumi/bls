@echo off
call setvar.bat
echo make bls.lib
rem cl /c %CFLAGS% src\bls.cpp
rem lib /OUT:lib\bls.lib /nodefaultlib bls.obj %LDFLAGS%
rem echo make bls256.lib
cl /c %CFLAGS% src\bls_c.cpp
rem lib /OUT:lib\bls256.lib /nodefaultlib bls_c.obj %LDFLAGS%
echo make bls256.dll
link /nologo /DLL /OUT:bin\bls256.dll bls_c.obj %LDFLAGS% /implib:lib\bls256.lib
