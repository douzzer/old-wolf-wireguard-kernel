#include "wolfcrypto_shim.h"

int curve25519_generate_public_wolfshim(uint8_t pub[static CURVE25519_KEY_SIZE], const uint8_t secret[static CURVE25519_KEY_SIZE]) {
    uint8_t secret_copy[CURVE25519_KEY_SIZE]; /* pubkey_main() calls curve25519_generate_public() with pub == secret, which doesn't work for wc_curve25519_make_pub(). */
    XMEMCPY(secret_copy, secret, CURVE25519_KEY_SIZE);
    return !wc_curve25519_make_pub(CURVE25519_KEY_SIZE, pub, CURVE25519_KEY_SIZE, secret_copy);
}

int curve25519_generate_secret_wolfshim(u8 secret[CURVE25519_KEY_SIZE]) {
  WC_RNG *gRng = wc_rng_new(NULL /* nonce */, 0 /* nonceSz */, NULL /*heap */);
  if (gRng) {
    (void)wc_curve25519_make_priv(gRng, (int)CURVE25519_KEY_SIZE, (byte *)secret);
    wc_rng_free(gRng);
    return 0;
  } else
    return -ENOMEM;
}
