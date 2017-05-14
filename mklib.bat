@echo off
call setvar.bat
echo make bls.lib
cl /c %CFLAGS% src\bls.cpp
lib /OUT:lib\bls.lib /nodefaultlib bls.obj %LDFLAGS%
rem echo make lib_if.lib
cl /c %CFLAGS% src\bls_if.cpp
rem lib /OUT:lib\bls_if.lib /nodefaultlib bls_if.obj %LDFLAGS%
echo make bls256.dll
link /nologo /DLL /OUT:bin\bls256.dll bls.obj bls_if.obj %LDFLAGS% /implib:lib\bls_if256.lib
