// Test-only primitive backend for SecureDirect, using OpenSSL. Not part of the firmware.
#include "SecureDirect.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cstring>

namespace meshport {

bool x25519PublicKey(const uint8_t priv[32], uint8_t pub[32])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    if (!k) return false;
    size_t len = 32;
    int ok = EVP_PKEY_get_raw_public_key(k, pub, &len);
    EVP_PKEY_free(k);
    return ok == 1 && len == 32;
}

bool x25519SharedSecret(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t shared[32])
{
    EVP_PKEY *mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    EVP_PKEY *theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPub, 32);
    bool ok = false;
    if (mine && theirs) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, nullptr);
        size_t len = 32;
        if (ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, theirs) == 1 &&
            EVP_PKEY_derive(ctx, shared, &len) == 1 && len == 32) {
            ok = true;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(mine);
    EVP_PKEY_free(theirs);
    return ok;
}

bool hkdfSha256(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen,
                const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, static_cast<int>(ikmLen)) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(saltLen)) == 1 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, info, static_cast<int>(infoLen)) == 1;
    size_t len = outLen;
    ok = ok && EVP_PKEY_derive(ctx, out, &len) == 1 && len == outLen;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool chachaPolySeal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, uint8_t tag[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0;
    bool ok = c && EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) == 1;
    if (ok && aadLen) ok = EVP_EncryptUpdate(c, nullptr, &n, aad, static_cast<int>(aadLen)) == 1;
    if (ok && len) ok = EVP_EncryptUpdate(c, data, &n, data, static_cast<int>(len)) == 1;
    if (ok) ok = EVP_EncryptFinal_ex(c, nullptr, &n) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

bool chachaPolyOpen(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadLen,
                    uint8_t *data, size_t len, const uint8_t tag[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0;
    bool ok = c && EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) == 1;
    if (ok && aadLen) ok = EVP_DecryptUpdate(c, nullptr, &n, aad, static_cast<int>(aadLen)) == 1;
    if (ok && len) ok = EVP_DecryptUpdate(c, data, &n, data, static_cast<int>(len)) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag)) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(c, nullptr, &n) == 1; // fails if the tag does not match
    EVP_CIPHER_CTX_free(c);
    return ok;
}

} // namespace meshport
