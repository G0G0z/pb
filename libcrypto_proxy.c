/**
 * libcrypto-1_1.dll — Proxy / Hook DLL
 * =====================================
 * Oyunun dizinine bu DLL'i "libcrypto-1_1.dll" adıyla koyun.
 * Gerçek libcrypto-1_1.dll'i "libcrypto-1_1_orig.dll" olarak yeniden adlandırın.
 *
 * Oyun bu DLL'i yüklediğinde:
 *   - BF_cfb64_encrypt  → plaintext + anahtar + IV loglanır, sonra gerçek şifreye iletilir
 *   - RSA_public_encrypt → session key loglanır (şifrelemeden önce)
 *   - Diğer tüm fonksiyonlar → direkt orijinale yönlendirilir
 *
 * Log dosyası: oyun dizininde pb_crypto.log
 *
 * Derleme (Replit'te):
 *   i686-w64-mingw32-gcc -shared -o libcrypto-1_1.dll libcrypto_proxy.c proxy_asm.s \
 *       -Wl,--kill-at -Wall -O2
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>

/* ── Gerçek DLL handle ── */
static HMODULE g_real = NULL;
static FILE   *g_log  = NULL;

/* ── OpenSSL tip tanımları (tam header gerekmez) ── */
typedef void   BF_KEY;
typedef void   RSA;
typedef void   BIO;

/* ── Gerçek fonksiyon pointer'ları ── */
typedef void   (*fn_BF_cfb64_encrypt)(const unsigned char*, unsigned char*,
                                       long, const BF_KEY*, unsigned char*,
                                       int*, int);
typedef int    (*fn_RSA_public_encrypt)(int, const unsigned char*,
                                        unsigned char*, RSA*, int);
typedef int    (*fn_RSA_size)(const RSA*);
typedef RSA*   (*fn_PEM_read_bio_RSAPublicKey)(BIO*, RSA**, void*, void*);
typedef BIO*   (*fn_BIO_new_mem_buf)(const void*, int);
typedef int    (*fn_BIO_free)(BIO*);
typedef void   (*fn_RSA_free)(RSA*);
typedef void   (*fn_RAND_seed)(const void*, int);

static fn_BF_cfb64_encrypt       real_BF_cfb64_encrypt       = NULL;
static fn_RSA_public_encrypt     real_RSA_public_encrypt     = NULL;
static fn_RSA_size               real_RSA_size               = NULL;
static fn_PEM_read_bio_RSAPublicKey real_PEM_read_bio_RSAPublicKey = NULL;
static fn_BIO_new_mem_buf        real_BIO_new_mem_buf        = NULL;
static fn_BIO_free               real_BIO_free               = NULL;
static fn_RSA_free               real_RSA_free               = NULL;
static fn_RAND_seed              real_RAND_seed              = NULL;

/* ── Yardımcı: hex dump ── */
static void log_hex(const char *label, const unsigned char *buf, int len) {
    if (!g_log || !buf || len <= 0) return;
    fprintf(g_log, "  %s [%d bytes]: ", label, len);
    int show = len > 64 ? 64 : len;
    for (int i = 0; i < show; i++) fprintf(g_log, "%02x", buf[i]);
    if (len > 64) fprintf(g_log, "...(+%d)", len - 64);
    fprintf(g_log, "\n");
}

static void log_timestamp(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

/* ════════════════════════════════════════════════
 *  HOOK — BF_cfb64_encrypt
 *  Bu fonksiyon her şifreli paket gönderme/alma'da çağrılır.
 *  in     = plaintext (gönderilecek/alınan ham veri)
 *  out    = ciphertext (şifrelenmiş çıktı)
 *  length = veri uzunluğu
 *  key    = Blowfish key struct (BF_set_key ile doldurulmuş)
 *  ivec   = 8-byte IV (CFB64 modu)
 *  num    = CFB modu offset sayacı
 *  enc    = BF_ENCRYPT(1) veya BF_DECRYPT(0)
 * ════════════════════════════════════════════════ */
__declspec(dllexport)
void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const BF_KEY *key,
                      unsigned char *ivec, int *num, int enc) {
    if (g_log) {
        log_timestamp();
        fprintf(g_log, "BF_cfb64_encrypt — %s, len=%ld\n",
                enc == 1 ? "ENCRYPT (gönderme)" : "DECRYPT (alma)", length);
        log_hex("ivec (IV)", ivec, 8);
        log_hex("in  (plaintext)", in, (int)length);
        /* key struct'ın ilk 72 bytes'ı P-array = etkin anahtar verisi */
        log_hex("key (P-array ilk 32B)", (const unsigned char*)key, 32);
        fflush(g_log);
    }

    /* Gerçek fonksiyona ilet */
    if (real_BF_cfb64_encrypt)
        real_BF_cfb64_encrypt(in, out, length, key, ivec, num, enc);

    if (g_log && enc == 0) {
        /* Decrypt sonrası çıktıyı da logla */
        log_hex("out (decrypted)", out, (int)length);
        fflush(g_log);
    }
}

/* ════════════════════════════════════════════════
 *  HOOK — RSA_public_encrypt
 *  Login/handshake sırasında Blowfish session key'i
 *  sunucunun RSA public key'i ile şifreler.
 *  flen = plaintext uzunluğu (= Blowfish key boyutu)
 *  from = plaintext (= Blowfish session key — ALTIN!)
 *  to   = RSA şifreli çıktı
 * ════════════════════════════════════════════════ */
__declspec(dllexport)
int RSA_public_encrypt(int flen, const unsigned char *from,
                       unsigned char *to, RSA *rsa, int padding) {
    if (g_log) {
        log_timestamp();
        fprintf(g_log, "RSA_public_encrypt — flen=%d padding=%d\n", flen, padding);
        log_hex("*** SESSION KEY (plaintext Blowfish key)", from, flen);
        fflush(g_log);
    }

    int ret = 0;
    if (real_RSA_public_encrypt)
        ret = real_RSA_public_encrypt(flen, from, to, rsa, padding);

    if (g_log) {
        log_hex("RSA encrypted output", to, ret > 0 ? ret : flen);
        fflush(g_log);
    }
    return ret;
}

/* ════════════════════════════════════════════════
 *  HOOK — PEM_read_bio_RSAPublicKey
 *  Sunucudan gelen RSA public key'i okur.
 *  Bu çağrı sonrası elimizde sunucunun public key'i var.
 * ════════════════════════════════════════════════ */
__declspec(dllexport)
RSA* PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, void *cb, void *u) {
    if (g_log) {
        log_timestamp();
        fprintf(g_log, "PEM_read_bio_RSAPublicKey — sunucu RSA public key okunuyor\n");
        fflush(g_log);
    }
    RSA *ret = NULL;
    if (real_PEM_read_bio_RSAPublicKey)
        ret = real_PEM_read_bio_RSAPublicKey(bp, x, cb, u);
    if (g_log) {
        fprintf(g_log, "  -> RSA* = %p (RSA_size=%d bit)\n",
                (void*)ret,
                (ret && real_RSA_size) ? real_RSA_size(ret) * 8 : -1);
        fflush(g_log);
    }
    return ret;
}

/* ── Basit yönlendirme fonksiyonları ── */
__declspec(dllexport)
int RSA_size(const RSA *rsa) {
    return real_RSA_size ? real_RSA_size(rsa) : 0;
}

__declspec(dllexport)
BIO* BIO_new_mem_buf(const void *buf, int len) {
    return real_BIO_new_mem_buf ? real_BIO_new_mem_buf(buf, len) : NULL;
}

__declspec(dllexport)
int BIO_free(BIO *a) {
    return real_BIO_free ? real_BIO_free(a) : 0;
}

__declspec(dllexport)
void RSA_free(RSA *r) {
    if (real_RSA_free) real_RSA_free(r);
}

__declspec(dllexport)
void RAND_seed(const void *buf, int num) {
    if (real_RAND_seed) real_RAND_seed(buf, num);
}

/* ════════════════════════════════════════════════
 *  DllMain — Yükleme / Kaldırma
 * ════════════════════════════════════════════════ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        /* Log dosyasını aç */
        g_log = fopen("pb_crypto.log", "a");
        if (g_log) {
            fprintf(g_log, "\n========================================\n");
            fprintf(g_log, "  libcrypto proxy yüklendi — PID %lu\n", GetCurrentProcessId());
            fprintf(g_log, "========================================\n");
            fflush(g_log);
        }

        /* Gerçek DLL'i yükle */
        g_real = LoadLibraryA("libcrypto-1_1_orig.dll");
        if (!g_real) {
            if (g_log) {
                fprintf(g_log, "HATA: libcrypto-1_1_orig.dll yuklenemedi! (LastError=%lu)\n",
                        GetLastError());
                fclose(g_log);
            }
            return FALSE;
        }

        /* Fonksiyon pointer'larını al */
#define LOAD(name) real_##name = (fn_##name)GetProcAddress(g_real, #name)
        LOAD(BF_cfb64_encrypt);
        LOAD(RSA_public_encrypt);
        LOAD(RSA_size);
        LOAD(PEM_read_bio_RSAPublicKey);
        LOAD(BIO_new_mem_buf);
        LOAD(BIO_free);
        LOAD(RSA_free);
        LOAD(RAND_seed);
#undef LOAD

        if (g_log) {
            fprintf(g_log, "Gercek DLL yuklendi: %p\n", (void*)g_real);
            fprintf(g_log, "BF_cfb64_encrypt      : %p\n", (void*)real_BF_cfb64_encrypt);
            fprintf(g_log, "RSA_public_encrypt    : %p\n", (void*)real_RSA_public_encrypt);
            fprintf(g_log, "PEM_read_bio_RSAPublicKey: %p\n", (void*)real_PEM_read_bio_RSAPublicKey);
            fflush(g_log);
        }

    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_log) {
            fprintf(g_log, "libcrypto proxy kaldırıldı.\n");
            fclose(g_log);
            g_log = NULL;
        }
        if (g_real) {
            FreeLibrary(g_real);
            g_real = NULL;
        }
    }
    return TRUE;
}
