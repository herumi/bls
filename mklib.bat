@echo off
echo make bls.lib
set OPT=/DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc /c -I./include -I../mcl/include -I../cybozulib/include -I../cybozulib_ext/include
cl %OPT% -DBLS_MAX_OP_UNIT_SIZE=4 src\bls.cpp
lib /OUT:lib\bls.lib /nodefaultlib bls.obj
echo make lib_if.lib
cl %OPT% -DBLS_MAX_OP_UNIT_SIZE=4 src\bls_if.cpp
lib /OUT:lib\bls_if.lib /nodefaultlib bls_if.obj
