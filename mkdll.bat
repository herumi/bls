@echo off
call setvar.bat
echo make bls256.dll
cl /LD src\bls_c.cpp ..\mcl\src\fp.cpp -Iinclude -I../mcl -I../xbyak -I../mcl/include -I../cybozulib/include -I../cybozulib_ext/include /MT /W4 /DMCLBN_FP_UNIT_SIZE=4 /Ox /EHsc /DNOMINMAX /DNDEBUG /DMCL_NO_AUTOLINK /link /out:bin\bls256.dll /implib:lib\bls256.lib /LIBPATH:..\cybozulib_ext\lib
