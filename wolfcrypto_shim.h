#ifndef WOLFCRYPTO_SHIM_H
#define WOLFCRYPTO_SHIM_H

#include <wolfssl/options.h>
#ifndef WOLFSSL_LINUXKM
#error libwolfssl configured without --enable-linuxkm
#endif
#ifndef HAVE_CURVE25519
#error libwolfssl missing HAVE_CURVE25519
#endif
#ifndef HAVE_BLAKE2S
#error libwolfssl missing HAVE_BLAKE2S
#endif
#ifndef HAVE_CHACHA
#error libwolfssl missing HAVE_CHACHA
#endif
#ifndef HAVE_POLY1305
#error libwolfssl missing HAVE_POLY1305
#endif

#undef SHA256_BLOCK_SIZE
#undef SHA256_DIGEST_SIZE
#undef SHA224_BLOCK_SIZE
#undef SHA224_DIGEST_SIZE
#undef CURVE25519_KEYSIZE

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#define CURVE25519_H
#define CURVE25519_KEY_SIZE CURVE25519_KEYSIZE

#include <wolfssl/wolfcrypt/chacha.h>
#define _CRYPTO_CHACHA_H

#include <wolfssl/wolfcrypt/poly1305.h>
#define _CRYPTO_POLY1305_H
#define CHACHA20POLY1305_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define CHACHA20POLY1305_AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE
#define XCHACHA20POLY1305_NONCE_SIZE 24 /* CHACHA20_POLY1305_AEAD_IV_SIZE * 2 */

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#define __CHACHA20POLY1305_H


#include <wolfssl/wolfcrypt/blake2.h>
#define BLAKE2S_H
#define BLAKE2S_HASH_SIZE BLAKE2S_256
#define BLAKE2S_BLOCK_SIZE 64


#include <linux/kconfig.h>
#include <linux/kernel.h>


struct blake2s_state {
  Blake2s blake2s;
};
#define blake2s_init(...) wg_blake2s_init(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_init(struct blake2s_state *state, size_t outlen) {
  (void)wc_InitBlake2s(&state->blake2s, (word32)outlen);
}
#define blake2s_init_key(...) wg_blake2s_init_key(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_init_key(struct blake2s_state *state, size_t outlen, const void *key,
                                                            const size_t keylen) {
  (void)wc_InitBlake2s_WithKey(&state->blake2s, (word32)outlen, (const byte *)key, (word32)keylen);
}
#define blake2s_update(...) wg_blake2s_update(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen) {
  (void)wc_Blake2sUpdate(&state->blake2s, (const byte *)in, (word32)inlen);
}
#define blake2s_final(...) wg_blake2s_final(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_final(struct blake2s_state *state, const u8 *out) {
  (void)wc_Blake2sFinal(&state->blake2s, (byte *)out, 0);
}

#define blake2s(...) wg_simple_blake2s(__VA_ARGS__)
static inline int blake2s(byte *out, const void *in, const void *key, const byte outlen,
             const word32 inlen, byte keylen)
{
  Blake2s state;

  if ((in == NULL) || (out == NULL))
    return -1;

  if (wc_InitBlake2s_WithKey(&state, (word32)outlen, (const byte *)key, (word32)keylen) < 0)
    return -1;
  if (wc_Blake2sUpdate(&state, (byte *)in, inlen) < 0)
    return -1;
  return wc_Blake2sFinal(&state, out, (word32)outlen);
}

#define blake2s256_hmac(...) wg_blake2s256_hmac(__VA_ARGS__)
static __attribute__((unused)) void blake2s256_hmac(byte *out, const byte *in, const byte *key, size_t inlen, size_t keylen) {
  Blake2s state;
  word32 x_key[BLAKE2S_BLOCK_SIZE / sizeof(word32)];
  word32 i_hash[BLAKE2S_HASH_SIZE / sizeof(word32)];
  int i;

  if (keylen > BLAKE2S_BLOCK_SIZE) {
    wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE);
    wc_Blake2sUpdate(&state, key, keylen);
    wc_Blake2sFinal(&state, (byte *)x_key, 0);
  } else {
    XMEMCPY(x_key, key, keylen);
    XMEMSET((byte *)x_key + keylen, 0, BLAKE2S_BLOCK_SIZE - keylen);
  }

  for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
    ((byte *)x_key)[i] ^= 0x36;

  wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE);
  wc_Blake2sUpdate(&state, (byte *)x_key, BLAKE2S_BLOCK_SIZE);
  wc_Blake2sUpdate(&state, in, inlen);
  wc_Blake2sFinal(&state, (byte *)i_hash, 0);

  for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
    ((byte *)x_key)[i] ^= 0x5c ^ 0x36;

  wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE);
  wc_Blake2sUpdate(&state, (byte *)x_key, BLAKE2S_BLOCK_SIZE);
  wc_Blake2sUpdate(&state, (byte *)i_hash, BLAKE2S_HASH_SIZE);
  wc_Blake2sFinal(&state, (byte *)i_hash, 0);

  XMEMCPY(out, i_hash, BLAKE2S_HASH_SIZE);
  XMEMSET(x_key, 0, BLAKE2S_BLOCK_SIZE);
  XMEMSET(i_hash, 0, BLAKE2S_HASH_SIZE);
}


#define curve25519_generate_public(...) curve25519_generate_public_wolfshim(__VA_ARGS__)
extern int curve25519_generate_public(uint8_t pub[static CURVE25519_KEYSIZE], const uint8_t secret[static CURVE25519_KEYSIZE]);

#define curve25519_generate_secret(...) curve25519_generate_secret_wolfshim(__VA_ARGS__)
extern int curve25519_generate_secret(u8 secret[CURVE25519_KEY_SIZE]);

#define curve25519_clamp_secret(...) curve25519_clamp_secret_wolfshim(__VA_ARGS__)
static inline void curve25519_clamp_secret(u8 key[CURVE25519_KEY_SIZE])
{
  key[0] &= 248;
  key[CURVE25519_KEY_SIZE-1] &= 63; /* same &=127 because |=64 after */
  key[CURVE25519_KEY_SIZE-1] |= 64;
}

#define curve25519(...) curve25519_wolfshim(__VA_ARGS__)
static inline bool curve25519(uint8_t mypublic[static CURVE25519_KEY_SIZE], const uint8_t secret[static CURVE25519_KEY_SIZE], const uint8_t basepoint[static CURVE25519_KEY_SIZE]) {
  return (wc_curve25519_generic(CURVE25519_KEY_SIZE, (byte *)mypublic, CURVE25519_KEY_SIZE, (byte *)secret, CURVE25519_KEY_SIZE, (byte *)basepoint) == 0 ? true : false);
}

static __attribute__((unused)) inline void
chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
                         const u8 *ad, const size_t ad_len,
                         const u64 nonce,
                         const u8 key[CHACHA20POLY1305_KEY_SIZE]) {
  word64 inIV[2] = { 0, cpu_to_le64(nonce) };
  wc_ChaCha20Poly1305_Encrypt(key, (byte *)inIV + sizeof inIV - CHACHA20_POLY1305_AEAD_IV_SIZE, ad, (word32)ad_len,
                              (const byte *)src, (word32)src_len,
                              (byte *)dst,
                              (byte *)dst + src_len);
}

static __attribute__((unused)) inline bool
chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
                         const u8 *ad, const size_t ad_len,
                         const u64 nonce,
                         const u8 key[CHACHA20POLY1305_KEY_SIZE]) {
  word64 inIV[2] = { 0, cpu_to_le64(nonce) };

  if (wc_ChaCha20Poly1305_Decrypt
      ((byte *)key,
       (byte *)inIV + sizeof inIV - CHACHA20_POLY1305_AEAD_IV_SIZE,
       (const byte *)ad,
       (word32)ad_len,
       (const byte *)src, (word32)src_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE,
       (const byte *)src + (word32)src_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE,
       (byte *)dst) < 0)
    return false;
  else
    return true;
}

#define xchacha20poly1305_encrypt(...) ({})
#define xchacha20poly1305_decrypt(...) false
#define chacha20poly1305_encrypt_sg_inplace(...) false
#define chacha20poly1305_decrypt_sg_inplace(...) false

#ifdef notyet

static __attribute__((unused)) inline void
xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
                          const u8 *ad, const size_t ad_len,
                          const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
                          const u8 key[CHACHA20POLY1305_KEY_SIZE]) {
//        u32 chacha_state[CHACHA_STATE_WORDS];
//        u32 k[CHACHA_KEY_WORDS];
        u8 iv[CHACHA20_POLY1305_AEAD_IV_SIZE];

  ChaCha *ctx = (Chacha *)malloc(sizeof *chacha_state);
  if (ctx == NULL)
    return;

//        chacha_load_key(k, key);
  if (wc_Chacha_SetKey(ctx, (const byte *)key, (word32)CHACHA20POLY1305_KEY_SIZE) < 0)
    return;

        memset(iv, 0, 8);
        memcpy(iv + 8, nonce + 16, 8);

        /* Compute the subkey given the original key and first 128 nonce bits */
//        chacha_init(chacha_state, k, nonce);
        if (wc_Chacha_SetIV(ctx, (const byte*)iv, 0 /*word32 counter*/) < 0)
          return;
        hchacha_block(chacha_state, k, 20);

        chacha_init(chacha_state, k, iv);
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)

        memzero_explicit(k, sizeof(k));
        memzero_explicit(iv, sizeof(iv));


//        __chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, chacha_state);
        wc_ChaCha20Poly1305_Encrypt(
}

bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
                               const u8 *ad, const size_t ad_len,
                               const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
                               const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
        u32 chacha_state[CHACHA_STATE_WORDS];

        xchacha_init(chacha_state, key, nonce);
        return __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len,
                                          chacha_state);
}

static
bool chacha20poly1305_crypt_sg_inplace(struct scatterlist *src,
                                       const size_t src_len,
                                       const u8 *ad, const size_t ad_len,
                                       const u64 nonce,
                                       const u8 key[CHACHA20POLY1305_KEY_SIZE],
                                       int encrypt)
{
        const u8 *pad0 = page_address(ZERO_PAGE(0));
        struct poly1305_desc_ctx poly1305_state;
        u32 chacha_state[CHACHA_STATE_WORDS];
        struct sg_mapping_iter miter;
        size_t partial = 0;
        unsigned int flags;
        bool ret = true;
        int sl;
        union {
                struct {
                        u32 k[CHACHA_KEY_WORDS];
                        __le64 iv[2];
                };
                u8 block0[POLY1305_KEY_SIZE];
                u8 chacha_stream[CHACHA_BLOCK_SIZE];
                struct {
                        u8 mac[2][POLY1305_DIGEST_SIZE];
                };
                __le64 lens[2];
        } b __aligned(16);

        if (WARN_ON(src_len > INT_MAX))
                return false;

        chacha_load_key(b.k, key);

        b.iv[0] = 0;
        b.iv[1] = cpu_to_le64(nonce);

        chacha_init(chacha_state, b.k, (u8 *)b.iv);
        chacha20_crypt(chacha_state, b.block0, pad0, sizeof(b.block0));
        poly1305_init(&poly1305_state, b.block0);

        if (unlikely(ad_len)) {
                poly1305_update(&poly1305_state, ad, ad_len);
                if (ad_len & 0xf)
                        poly1305_update(&poly1305_state, pad0, 0x10 - (ad_len & 0xf));
        }

        flags = SG_MITER_TO_SG;
        if (!preemptible())
                flags |= SG_MITER_ATOMIC;

        sg_miter_start(&miter, src, sg_nents(src), flags);

        for (sl = src_len; sl > 0 && sg_miter_next(&miter); sl -= miter.length) {
                u8 *addr = miter.addr;
                size_t length = min_t(size_t, sl, miter.length);

                if (!encrypt)
                        poly1305_update(&poly1305_state, addr, length);

                if (unlikely(partial)) {
                        size_t l = min(length, CHACHA_BLOCK_SIZE - partial);

                        crypto_xor(addr, b.chacha_stream + partial, l);
                        partial = (partial + l) & (CHACHA_BLOCK_SIZE - 1);

                        addr += l;
                        length -= l;
                }

                if (likely(length >= CHACHA_BLOCK_SIZE || length == sl)) {
                        size_t l = length;

                        if (unlikely(length < sl))
                                l &= ~(CHACHA_BLOCK_SIZE - 1);
                        chacha20_crypt(chacha_state, addr, addr, l);
                        addr += l;
                        length -= l;
                }

                if (unlikely(length > 0)) {
                        chacha20_crypt(chacha_state, b.chacha_stream, pad0,
                                       CHACHA_BLOCK_SIZE);
                        crypto_xor(addr, b.chacha_stream, length);
                        partial = length;
                }

                if (encrypt)
                        poly1305_update(&poly1305_state, miter.addr,
                                        min_t(size_t, sl, miter.length));
        }

        if (src_len & 0xf)
                poly1305_update(&poly1305_state, pad0, 0x10 - (src_len & 0xf));

        b.lens[0] = cpu_to_le64(ad_len);
        b.lens[1] = cpu_to_le64(src_len);
        poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens));

        if (likely(sl <= -POLY1305_DIGEST_SIZE)) {
                if (encrypt) {
                        poly1305_final(&poly1305_state,
                                       miter.addr + miter.length + sl);
                        ret = true;
                } else {
                        poly1305_final(&poly1305_state, b.mac[0]);
                        ret = !crypto_memneq(b.mac[0],
                                             miter.addr + miter.length + sl,
                                             POLY1305_DIGEST_SIZE);
                }
        }

        sg_miter_stop(&miter);

        if (unlikely(sl > -POLY1305_DIGEST_SIZE)) {
                poly1305_final(&poly1305_state, b.mac[1]);
                scatterwalk_map_and_copy(b.mac[encrypt], src, src_len,
                                         sizeof(b.mac[1]), encrypt);
                ret = encrypt ||
                      !crypto_memneq(b.mac[0], b.mac[1], POLY1305_DIGEST_SIZE);
        }

        memzero_explicit(chacha_state, sizeof(chacha_state));
        memzero_explicit(&b, sizeof(b));

        return ret;
}

bool chacha20poly1305_encrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                         const u8 *ad, const size_t ad_len,
                                         const u64 nonce,
                                         const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
        return chacha20poly1305_crypt_sg_inplace(src, src_len, ad, ad_len,
                                                 nonce, key, 1);
}

bool chacha20poly1305_decrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                         const u8 *ad, const size_t ad_len,
                                         const u64 nonce,
                                         const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
        if (unlikely(src_len < POLY1305_DIGEST_SIZE))
                return false;

        return chacha20poly1305_crypt_sg_inplace(src,
                                                 src_len - POLY1305_DIGEST_SIZE,
                                                 ad, ad_len, nonce, key, 0);
}

#endif /* notyet */

#endif
