@echo off
setlocal
if "%~1"=="" goto usage
if "%~2"=="" goto usage
if not exist "%~2\." goto usage
set "reproDmd=%~1"
pushd "%~2"
if errorlevel 1 exit /b 2
ml64 /nologo /c "%~dp0call-probe.asm"
if errorlevel 1 goto failed
cl /nologo /W4 /WX /EHsc /O2 /Feentry-check.exe "%~dp0entry-check.cpp" call-probe.obj /link /INCREMENTAL:NO
if errorlevel 1 goto failed
call :compile optimized -O
if errorlevel 1 goto failed
call :compile betterc -betterC -O
if errorlevel 1 goto failed
call :compile debug -g
if errorlevel 1 goto failed
call :compile framed -O -gs
if errorlevel 1 goto failed
call :assemble leaf-control
if errorlevel 1 goto failed
call :assemble frame-control
if errorlevel 1 goto failed
popd
exit /b 0

:compile
"%reproDmd%" -m64 -c -ofprobe-%1.obj %2 %3 "%~dp0probe.d"
if errorlevel 1 exit /b 2
link /nologo /dll /noentry /nodefaultlib /INCREMENTAL:NO /out:probe-%1.dll /export:probe probe-%1.obj
exit /b %errorlevel%

:assemble
ml64 /nologo /c "%~dp0%1.asm"
if errorlevel 1 exit /b 2
link /nologo /dll /noentry /nodefaultlib /INCREMENTAL:NO /out:%1.dll /export:probe %1.obj
exit /b %errorlevel%

:failed
popd
exit /b 2

:usage
echo Run from an x64 Visual Studio tools prompt.
echo Usage: build.cmd path-to-dmd.exe existing-output-directory
exit /b 2
