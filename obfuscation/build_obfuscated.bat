@echo off
setlocal enabledelayedexpansion

:: =====================================================
:: LIBERTEA.DLL — Obfuscated Build Script
:: Uses Clang-CL as drop-in replacement for MSVC cl.exe
:: Links with standard MSVC link.exe
:: =====================================================

:: --- Configuration ---
set LLVM_DIR=C:\Program Files\LLVM
set PROJECT_ROOT=%~dp0..
set OBFUSCATION_DIR=%~dp0
set PASSES_DIR=%OBFUSCATION_DIR%passes

set OBFUSCATION_DLL=%PASSES_DIR%\obfuscation.dll

:: --- Source files ---
set SOURCES=%PROJECT_ROOT%\src\main.cpp
:: Add additional source files here:
:: set SOURCES=%SOURCES% %PROJECT_ROOT%\src\module1.cpp
:: set SOURCES=%SOURCES% %PROJECT_ROOT%\src\module2.cpp

:: --- Output ---
set OUTPUT_DIR=%PROJECT_ROOT%\out
set TARGET_NAME=liberta_obf.dll
set TARGET=%OUTPUT_DIR%\%TARGET_NAME%

set DEPS_DIR=%PROJECT_ROOT%\deps

:: --- Step 0: Verify Clang-CL is available ---
where clang-cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] clang-cl.exe not found on PATH.
    echo         Install LLVM 18+ from https://github.com/llvm/llvm-project/releases
    echo         or run: choco install llvm
    echo.
    echo         Attempting to use LLVM_DIR: %LLVM_DIR%
    if exist "%LLVM_DIR%\bin\clang-cl.exe" (
        set "PATH=%LLVM_DIR%\bin;%PATH%"
    ) else (
        exit /b 1
    )
)

:: --- Step 1: Build obfuscation passes (if not built) ---
if not exist "%OBFUSCATION_DLL%" (
    echo [BUILD] Obfuscation pass plugin not found. Building from source...
    pushd "%PASSES_DIR%"
    
    set LLVM_INCLUDE=%LLVM_DIR%\include
    set LLVM_LIB=%LLVM_DIR%\lib
    
    clang-cl.exe /EHsc /std:c++20 /MD ^
        /I"%LLVM_INCLUDE%" ^
        /I"%LLVM_INCLUDE%\llvm" ^
        /D "LLVM_PLUGIN" ^
        /LD ^
        string_encrypt.cpp cfg_flatten.cpp bogus_cfg.cpp function_split.cpp ^
        /Fe:obfuscation.dll ^
        /link /LIBPATH:"%LLVM_LIB%" LLVM-C.lib
    
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to build obfuscation passes.
        popd
        exit /b 1
    )
    popd
) else (
    echo [SKIP] Obfuscation pass plugin found: %OBFUSCATION_DLL%
)

:: --- Step 2: Create output directory ---
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

:: --- Step 3: Compile with obfuscation ---
echo [BUILD] Compiling with Clang-CL + OLLVM passes...

:: Base MSVC-compatible flags
set CLANG_CL_FLAGS=/nologo /O2 /MT /GS- /EHsc /GR- /W0
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /fpass-plugin="%OBFUSCATION_DLL%"
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -enable-cfg-flatten
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -enable-string-encrypt
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -enable-bogus-cfg
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -enable-function-split

:: Per-function pass control via attributes:
:: To exclude a function: __declspec(no_bogus_cfg) etc.
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -bogus-cfg-probability=40
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -flatten-threshold=10
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% -mllvm -split-threshold=20

:: Include paths
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /I"%PROJECT_ROOT%\src"
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /I"%PROJECT_ROOT%\deps\include"

:: Defines
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /D "NDEBUG"
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /D "_CRT_SECURE_NO_WARNINGS"
set CLANG_CL_FLAGS=%CLANG_CL_FLAGS% /D "LIBERTEA_OBFUSCATED"

:: Compile
echo clang-cl.exe %CLANG_CL_FLAGS% /c %SOURCES%
clang-cl.exe %CLANG_CL_FLAGS% /c %SOURCES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed.
    exit /b 1
)

:: --- Step 4: Link with MSVC link.exe ---
echo [BUILD] Linking with MSVC link.exe...

:: Collect .obj files
set OBJ_FILES=
for %%f in (%SOURCES%) do (
    set "OBJ_FILES=!OBJ_FILES! %%~nf.obj"
)

set LINK_FLAGS=/nologo /DLL /OUT:"%TARGET%"
set LINK_FLAGS=%LINK_FLAGS% /MACHINE:X64
set LINK_FLAGS=%LINK_FLAGS% /SUBSYSTEM:WINDOWS
set LINK_FLAGS=%LINK_FLAGS% /OPT:REF /OPT:ICF

:: Additional libraries
set LINK_FLAGS=%LINK_FLAGS% /LIBPATH:"%DEPS_DIR%\lib"

echo link.exe %LINK_FLAGS% %OBJ_FILES%
link.exe %LINK_FLAGS% %OBJ_FILES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Linking failed.
    exit /b 1
)

:: --- Step 5: Strip and sign ---
echo [BUILD] Stripping symbols...
if exist "%LLVM_DIR%\bin\llvm-objcopy.exe" (
    "%LLVM_DIR%\bin\llvm-objcopy.exe" --strip-all "%TARGET%" "%TARGET:.dll=_stripped.dll%"
) else (
    echo [WARN] llvm-objcopy not found, skipping strip.
)

:: --- Step 6: Verify output ---
echo [BUILD] Verifying output...
if exist "%TARGET%" (
    for %%F in ("%TARGET%") do (
        echo [OK] Output: %TARGET% (%%~zF bytes)
    )
) else (
    echo [ERROR] Output file not found: %TARGET%
    exit /b 1
)

echo.
echo =============================================
echo  BUILD COMPLETE — %TARGET_NAME%
echo =============================================
echo  Obfuscation passes applied:
echo    - String Encryption     [ENABLED]
echo    - CFG Flattening        [ENABLED]
echo    - Bogus CFG             [ENABLED]
echo    - Function Split        [ENABLED]
echo =============================================

endlocal
