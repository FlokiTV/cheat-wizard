@echo off
setlocal
cd /d "%~dp0"
call build-release.bat
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Automated tests ===
ctest --test-dir build -C Release --output-on-failure
if errorlevel 1 exit /b %errorlevel%
echo.
echo TESTS PASSED
