@echo off
set MCL_DIR=./mcl
call setvar.bat
set LOCAL_CFLAGS=%BLS_CFLAGS%
if "%1"=="-s" (
  echo use static lib
  set LOCAL_CFLAGS=%LOCAL_CFLAGS% /DBLS_DONT_EXPORT /DMCL_DONT_EXPORT
  shift
) else if "%1"=="-d" (
  echo use dynamic lib
  set LOCAL_CFLAGS=%LOCAL_CFLAGS%
  shift
) else (
  echo "mk (-s|-d) [eth] <source file>"
  goto exit
)
if "%1"=="eth" (
  echo make ETH mode
  set LOCAL_CFLAGS=%LOCAL_CFLAGS% -DBLS_ETH=1
  shift
)

set SRC=%1
set EXE=%SRC:.cpp=.exe%
set EXE=%EXE:.c=.exe%
set EXE=%EXE:test\=bin\%
set EXE=%EXE:sample\=bin\%
echo cl %LOCAL_CFLAGS% %1 /Fe:%EXE% /link %LDFLAGS%
cl %LOCAL_CFLAGS% %1 /Fe:%EXE% /link %LDFLAGS%

:exit
