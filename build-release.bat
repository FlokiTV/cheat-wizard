@echo off
setlocal
cd /d "%~dp0"
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
if errorlevel 1 exit /b %errorlevel%
cmake --build build --config Release
if errorlevel 1 exit /b %errorlevel%
echo.
echo Built:
echo   build\Release\cw.exe
echo   build\Release\Cheat Wizard.exe
echo   build\Release\cw-trainer-builder.exe
endlocal
