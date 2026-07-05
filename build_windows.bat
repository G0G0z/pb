@echo off
REM =====================================================
REM  libcrypto-1_1.dll Proxy — Windows Derleme Scripti
REM  MinGW (MSYS2) veya MSVC ile çalışır
REM =====================================================

echo.
echo === libcrypto proxy DLL derleniyor ===
echo.

REM --- MinGW ile derleme (MSYS2 kuruluysa) ---
where i686-w64-mingw32-gcc >nul 2>&1
if %errorlevel%==0 (
    echo MinGW bulundu, derleniyor...
    i686-w64-mingw32-gcc -shared -m32 -O2 ^
        -o libcrypto-1_1.dll ^
        libcrypto_proxy.c ^
        libcrypto_proxy.def ^
        -Wl,--kill-at ^
        -Wall
    goto :done
)

REM --- MSYS2 MinGW32 ile ---
where gcc >nul 2>&1
if %errorlevel%==0 (
    echo gcc bulundu, derleniyor...
    gcc -shared -m32 -O2 ^
        -o libcrypto-1_1.dll ^
        libcrypto_proxy.c ^
        libcrypto_proxy.def ^
        -Wl,--kill-at ^
        -Wall
    goto :done
)

echo HATA: MinGW bulunamadi.
echo Lutfen MSYS2 kurun: https://www.msys2.org/
echo Kurulumdan sonra: pacman -S mingw-w64-i686-gcc
goto :end

:done
if exist libcrypto-1_1.dll (
    echo.
    echo Basarili! libcrypto-1_1.dll olusturuldu.
    echo.
    echo --- KURULUM ADIMLARI ---
    echo 1. Oyun dizinine git (PointBlank.exe'nin oldugu yer)
    echo 2. libcrypto-1_1.dll'i  ->  libcrypto-1_1_orig.dll  yap (yeniden adlandir)
    echo 3. Bu klasordeki libcrypto-1_1.dll'i oyun dizinine kopyala
    echo 4. Oyunu calistir (normal sekilde)
    echo 5. pb_crypto.log dosyasini incele
    echo.
    echo Blowfish session key, pb_crypto.log icinde gorunecek.
) else (
    echo Derleme basarisiz!
)

:end
pause
