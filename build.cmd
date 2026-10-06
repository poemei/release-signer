@echo off
setlocal

cd /d "%~dp0"

set "CC=cl"
set "OUTDIR=build"
set "TARGET=%OUTDIR%\release-signer.exe"
set "OPENSSL_LIB_DIR=%OPENSSL_ROOT_DIR%\lib\VC\x64\MD"
set "OPENSSL_APPLINK=%OPENSSL_ROOT_DIR%\include\openssl\applink.c"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

where %CC% >nul 2>nul
if errorlevel 1 (
    echo [FAIL] Microsoft C compiler ^(cl.exe^) was not found.
    echo [INFO] Run this build from a Visual Studio x64 Developer Command Prompt.
    exit /b 1
)

if not defined OPENSSL_ROOT_DIR (
    echo [FAIL] OPENSSL_ROOT_DIR is not set.
    echo [INFO] Set OPENSSL_ROOT_DIR to the OpenSSL installation directory.
    echo [INFO] Expected:
    echo        %%OPENSSL_ROOT_DIR%%\include
    echo        %%OPENSSL_ROOT_DIR%%\lib\VC\x64\MD
    exit /b 1
)

if not exist "%OPENSSL_ROOT_DIR%\include\openssl\evp.h" (
    echo [FAIL] OpenSSL headers were not found under:
    echo        %OPENSSL_ROOT_DIR%\include
    exit /b 1
)

if not exist "%OPENSSL_APPLINK%" (
    echo [FAIL] OpenSSL applink source was not found:
    echo        %OPENSSL_APPLINK%
    exit /b 1
)

if not exist "%OPENSSL_LIB_DIR%\libcrypto.lib" (
    echo [FAIL] OpenSSL release library was not found:
    echo        %OPENSSL_LIB_DIR%\libcrypto.lib
    exit /b 1
)

echo [INFO] Building ChAoS Release Signer...

%CC% /nologo /W4 /O2 /TC ^
    /I"includes" ^
    /I"%OPENSSL_ROOT_DIR%\include" ^
    src\main.c ^
    src\keys.c ^
    src\sha256.c ^
    src\release.c ^
    "%OPENSSL_APPLINK%" ^
    /Fe:"%TARGET%" ^
    /link ^
    /LIBPATH:"%OPENSSL_LIB_DIR%" ^
    libcrypto.lib

if errorlevel 1 (
    echo [FAIL] Build failed.
    exit /b 1
)

if not exist "%TARGET%" (
    echo [FAIL] Compiler completed without producing %TARGET%.
    exit /b 1
)

echo [PASS] Build complete.
echo [PASS] %TARGET%

exit /b 0
