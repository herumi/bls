@echo off
cl /DNOMINMAX /Ox /DNDEBUG /W4 /Zi /EHsc -I ./include -I../mcl/include -I../cybozulib/include -I../cybozulib_ext/include -DBLS_MAX_OP_UNIT_SIZE=4 %1 %2 %3 /link /LIBPATH:..\cybozulib_ext\lib /LIBPATH:.\lib /LIBPATH:..\mcl\lib
