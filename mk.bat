@echo off
call setvar.bat
set SRC=%1
set EXE=%SRC:.cpp=.exe%
set EXE=%EXE:.c=.exe%
set EXE=%EXE:test\=bin\%
set EXE=%EXE:sample\=bin\%
cl %CFLAGS% %1 %2 %3 /Fe:%EXE% /link %LDFLAGS%
rem cl %1 -I../cybozulib/include /EHsc -Iinclude -I../mcl/include /DMCLBN_FP_UNIT_SIZE=4 /Fe:%EXE% /link /libpath:lib
